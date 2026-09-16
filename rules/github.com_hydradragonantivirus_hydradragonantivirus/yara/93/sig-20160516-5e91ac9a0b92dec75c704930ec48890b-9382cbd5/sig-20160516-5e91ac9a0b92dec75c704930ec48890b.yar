rule sig_20160516_5e91ac9a0b92dec75c704930ec48890b {
  meta:
    description = "datamaliciousorder - file 20160516_5e91ac9a0b92dec75c704930ec48890b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b6503d57662fc892bfc37a7aae1fe68690876699b9d57f292098d252dc63684e"

  strings:
    $s1  = "var judicature = [dexterously, pomegranate,focused,  \"\"+\".\"+(\"accent\",\"purplish\",\"dramatically\",\"contemporaneous\",\"" ascii
    $s2  = "var tickets=(\"\"+WScript==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".learned4())&&tortoise[\"c3RhdHVz\".learned4()] +\"\"==\"MjAw\".learn" ascii
    $s3  = "var tickets=(\"\"+WScript==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".learned4())&&tortoise[\"c3RhdHVz\".learned4()] +\"\"==\"MjAw\".learn" ascii
    $s4  = "        var summaries = new auditorium(((\"concrete\",\"storage\",\"exclusively\",\"typewriter\",\"sagacious\",\"specializing\"," ascii
    $s5  = "weasel = ((\"terminal\", \"common\", \"entitle\", \"continuously\", \"EjcbeHMM\") + \"TRfSUYEo\").learned2();" fullword ascii
    $s6  = "equilibrium = ((\"drivers\", \"barter\", \"canada\", \"failure\", \"pzzyqyaz\") + \"jBcFTf\").learned2();" fullword ascii
    $s7  = "lassitude = ((\"scimitar\", \"abridge\", \"mines\", \"swedish\", \"szuLrjvL\") + \"EytgDf\").learned2();" fullword ascii
    $s8  = "unpretending(\"aHR0cDovLw==\".learned4()+\"\\u0061\\u0064\\u0062\\u006D\\u002E\\u0063\\u006F\\u002E\\u0075\"+\"\\u006B\\u002F\\u" ascii
    $s9  = "String.prototype.learned4 = function() {" fullword ascii
    $s10 = "String.prototype.learned = function () {" fullword ascii
    $s11 = "var judicature = [dexterously, pomegranate,focused,  \"\"+\".\"+(\"accent\",\"purplish\",\"dramatically\",\"contemporaneous\",\"" ascii
    $s12 = "String.prototype.learned2 = function () {" fullword ascii
    $s13 = "function unpretending(quorum, genealogical) {" fullword ascii
    $s14 = "        var demolished = worried + \"/\" + genealogical ;" fullword ascii
    $s15 = "var ardently = new auditorium(testament[1]);" fullword ascii
    $s16 = "unpretending(\"aHR0cDovLw==\".learned4()+\"\\u0061\\u0064\\u0062\\u006D\\u002E\\u0063\\u006F\\u002E\\u0075\"+\"\\u006B\\u002F\\u" ascii
    $s17 = "var related = {" fullword ascii
    $s18 = "var tortoise = new auditorium(testament[0]);" fullword ascii
    $s19 = ")](malachi, timorous);" fullword ascii
    $s20 = "for (var i in related){smooth = smooth.replace(i, related[i]);}" fullword ascii

  condition:
    uint16(0) == 0x6c4b and
    8 of them
}