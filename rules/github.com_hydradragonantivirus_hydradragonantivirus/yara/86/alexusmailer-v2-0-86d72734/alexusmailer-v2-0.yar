rule alexusMailer_v2_0 {
  meta:
    description = "Tryag-File-Manager-jpeg-master - file alexusMailer_v2.0.php"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara"
    date        = "2018-07-14"
    hash1       = "82572013074747e079cde069ab95af8b20b597aaf76eeb892dc383a58be24620"

  strings:
    $x1  = "</span><br>\"),$(\"#out_servers\").val($(\"#out_servers\").val()+b.server+\"\\n\")):$(\"#pingout_log\").html(c+\"<span style='co" ascii
    $x2  = "}b.merge(d,s.childNodes),s.textContent=\"\";while(s.firstChild)s.removeChild(s.firstChild);s=f.lastChild}else d.push(t.createTex" ascii
    $x3  = "*/(function(n){function vi(t){var i=this,e=t.target,y=n.data(e,a),p=s[y],w=p.popupName,k=f[w],v,b;if(!i.disabled&&n(e).attr(r)!=" ascii
    $x4  = "if(\"undefined\"==typeof jQuery)throw new Error(\"Bootstrap's JavaScript requires jQuery\");+function(a){\"use strict\";function" ascii
    $x5  = "return(!i||i!==r&&!b.contains(r,i))&&(e.type=o.origType,n=o.handler.apply(this,arguments),e.type=t),n}}}),b.support.submitBubble" ascii
    $x6  = "!function(a,b){\"use strict\";\"function\"==typeof define&&define.amd?define([\"jquery\"],b):\"object\"==typeof exports?module.e" ascii
    $x7  = "(function(e,t){var n,r,i=typeof t,o=e.document,a=e.location,s=e.jQuery,u=e.$,l={},c=[],p=\"1.9.1\",f=c.concat,d=c.push,h=c.slice" ascii
    $x8  = "body{background-color:#fff}.content{margin:0 auto;background-color:#fcf2d4;width:1000px;padding:5px;border:1px solid #000;border" ascii
    $x9  = ": http://serv4.ru/sw.php|c99|login:password<?php endif;?>\"  <?php if(SERVICEMODE):?>readonly<?php endif;?>></textarea><br>" fullword ascii
    $x10 = "\"error\"=>$translation->getWord(\"shell-sheck-test-command-execution-failed\")" fullword ascii
    $x11 = "'shell-sheck-test-command-execution-failed'=>'Test command execution failed'," fullword ascii
    $x12 = "On the Configuration tab of external servers is available quick check of shells, it checks that the addresses are correct, passw" ascii
    $x13 = "ach(function(){d.offsets.push(this[0]),d.targets.push(this[1])})},b.prototype.process=function(){var a,b=this.$scrollElement.scr" ascii
    $s14 = "\"echo file_get_contents(\\'http://google.com/humans.txt\\');\" " fullword ascii
    $s15 = "* Bootstrap v3.2.0 (http://getbootstrap.com)" fullword ascii
    $s16 = "'shell-sheck-test-command-execution-failed'=>'" fullword ascii
    $s17 = "* Licensed under MIT (https://github.com/twbs/bootstrap/blob/master/LICENSE)" fullword ascii
    $s18 = "return $shellManager->exec($type, $url, $code, $data, $pass, isset($login)?$login:null);" fullword ascii
    $s19 = "$answer=$shellManager->exec($type, $url, $testcode, $data, $pass, isset($login)?$login:null);" fullword ascii
    $s20 = "command. Try using the keyboard shortcut or context menu instead.\",f):ut(n,l?l:\"Error executing the \"+i+\" command.\",f))}ret" ascii

  condition:
    (uint16(0) == 0x3f3c and
      filesize < 2000KB and
      (1 of ($x*) and all of them)
    ) or (all of them)
}