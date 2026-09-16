rule PAYPAL_PHISHING_001_infected_06_08_18_case127_files_thnks {
  meta:
    description = "case127 - file thnks.php"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara"
    date        = "2018-06-08"
    hash1       = "bb2b6b173f380d6e76f12dea48447d53632d2cd5dc9c73807139dfab8510778e"

  strings:
    $x1  = "</ul></section></div></div></div></div></div></div><div id=\"footer\" class=\"noPrint nemo_footer vx_globalFooter-container\" ro" ascii
    $x2  = "<script type=\"text/javascript\" src=\"./PayPal_ Summary1_files/customer.js.download\" async=\"\"></script><script type=\"text/j" ascii
    $x3  = "</span></a></div></div></div></div><a href=\"###\" class=\"js_dismiss emClose nemo_emClose\" role=\"button\" name=\"EM_DownloadA" ascii
    $x4  = "<!-- saved from url=(0077)file:///C:/Users/SpreadWorm/Desktop/Nouveau%20dossier/PayPal_%20Summary1.html -->" fullword ascii
    $s5  = "nemo_appSelect\"><span class=\"icon icon-medium icon-phone\" aria-hidden=\"true\"></span>Get the PayPal app</a></li><li class=\"" ascii
    $s6  = "<meta http-equiv=\"Refresh\" content=\"5;url=https://www.paypal.com/\">" fullword ascii
    $s7  = "aypalobjects.com/web/res/d9b/206b83f3021b1e1580a97bf54ed58/templates/US/en/widgets/ajaxError.js\" src=\"./PayPal_ Summary1_files" ascii
    $s8  = "s free in the U.S. when you use bank or balance.</p></div></div></div><a href=\"###\" class=\"js_dismiss emClose nemo_emClose\" " ascii
    $s9  = "<html dir=\"ltr\" class=\"js\" lang=\"en_US\"><head><meta http-equiv=\"Content-Type\" content=\"text/html; charset=UTF-8\">" fullword ascii
    $s10 = "ve covered the basics, have fun <a href=\"##/deals\" target=\"_top\" class=\"popover-link\" name=\"QT_Shopping\" data-pagename=" ascii
    $s11 = "<span class=\"numeralLabel vx_text-body_secondary balanceModule-zeroBalanceText\">No balance needed to shop or send money</span>" ascii
    $s12 = "3526d928f1ae21749d.js.download\"></script><!--Script info: script: node, template:  , date: Nov 19, 2016 18:02:58 -08:00, countr" ascii
    $s13 = "indow.Intl) { document.write('<script src=\"https://www.paypalobjects.com/web/res/d9b/206b83f3021b1e1580a97bf54ed58/js/lib/shim/" ascii
    $s14 = "A2gPn7kuC5R7jkFaE1mnvPPZcEM\" data-cobrowser=\"{&quot;serverHostUrl&quot;:&quot;https://cb.paypal.com&quot;,&quot;assetHostUrl&q" ascii
    $s15 = "$(this).parent().parent().find('.cc-ddl-o select').attr('selectedIndex', $('.cc-ddl-contents a').index(this));" fullword ascii
    $s16 = "eb/res/d9b/206b83f3021b1e1580a97bf54ed58/templates/US/en/widgets/ajaxError.js\" src=\"./PayPal_ Summary1_files/ajaxError.js(3).d" ascii
    $s17 = "-js-path=\"https://www.paypalobjects.com/web/res/ data-genericerror=\"Please try again.\" data-rlogid=\"GBuHKhnr0kktkGV1HgQNR%2F" ascii
    $s18 = "dule=\"https://www.paypalobjects.com/web/res/d9b/206b83f3021b1e1580a97bf54ed58/templates/US/en/dust-templates.js\" src=\"./PayPa" ascii
    $s19 = "plates/US/en/widgets/ajaxError.js\" src=\"./PayPal_ Summary1_files/ajaxError.js.download\"></script><script type=\"text/javascri" ascii
    $s20 = "ta-requirecontext=\"_\" data-requiremodule=\"https://www.paypalobjects.com/web/res/d9b/206b83f3021b1e1580a97bf54ed58/templates/U" ascii

  condition:
    (uint16(0) == 0x213c and
      filesize < 200KB and
      (1 of ($x*) and 4 of them)
    ) or (all of them)
}