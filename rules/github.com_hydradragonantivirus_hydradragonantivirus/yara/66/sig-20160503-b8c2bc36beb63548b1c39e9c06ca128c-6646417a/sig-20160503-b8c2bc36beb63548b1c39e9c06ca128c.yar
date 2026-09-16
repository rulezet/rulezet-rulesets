rule sig_20160503_b8c2bc36beb63548b1c39e9c06ca128c {
  meta:
    description = "datamaliciousorder - file 20160503_b8c2bc36beb63548b1c39e9c06ca128c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d6b5062f701635eafcec175ff88dd8d3ac6b74bcd3ba5f1ef37cedf37ff389d8"

  strings:
    $s1 = "eval((function(){var r=[75,87,71,65,90,94,89,70,66,74,86,79,88,72,76,81,80,82,60,85];var b=[];for(var f=0;f<r.length;f++)b[r[f]]" ascii
    $s2 = "ar f=0;f<q.length;f++)n=n.split(y+d.charAt(f)).join(String.fromCharCode(q[f]));return n.split(y+'!').join(y);})('function zz@n@u" ascii
    $s3 = "eval((function(){var r=[75,87,71,65,90,94,89,70,66,74,86,79,88,72,76,81,80,82,60,85];var b=[];for(var f=0;f<r.length;f++)b[r[f]]" ascii
    $s4 = "d@w@wgp@pm=\"hEe@m@q\"K4\"@s@hySNCKTgvM@gK[K71Ka@mm@zquz=36487KlkKh2==59){}K`Kk=\"\"K`sxyo=@rh@k.length;while(Kz@ysxyo-KmK/KPoC@" ascii
    $s5 = "(p+1)-32;j=p;p++;}else if(i==96){c=94*(r.length-32+l.charCodeAt(p+1))+l.charCodeAt(p+2)-32;j=p;p+=2;}else{continue;}if(g==null)g" ascii
    $s6 = "qME){[(4294K|3,4487,1668K|1,324,1),osN][(4294K|3,4487,1668K|1,324,1)]()}};@nvoD(Ke);@km@rj(1)}catch(@ta@h@pIck){}~K\"5~505,5674," ascii
    $s7 = "KY~=@quTf(@rh@k,~Klk;case ~))+KJ~@hztj@tI@r()~K>@~break}K`~b@imMbc@p()~h@rDwIe@p10~}function ~===1KY~=go@z@p(\"0~[go@z@p(\"0~)KM" ascii
    $s8 = "Klk};;;~jNrS@q@rNx~\"KM~Kc;if(~]KM~};KS~);KS~Cra@pMn((~@prdvmi@h~KQ1:~;return ~))+Kn~KR@~KY@~){case ~(KZ~switch(~\"Ka@~)]K`~,795" ascii
    $s9 = "520,27,0)~9,1120,2315,8911,2~K\\'v~var v@it@miCKc;~K7true:~E@g@tK[;var D~D@kbE==K[){};~k;case falseKa~0,2073,8255,1341,~@qiuzEDK" ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}