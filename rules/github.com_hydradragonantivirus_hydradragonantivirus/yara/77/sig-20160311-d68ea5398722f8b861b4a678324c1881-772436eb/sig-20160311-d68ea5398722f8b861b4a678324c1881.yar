rule sig_20160311_d68ea5398722f8b861b4a678324c1881 {
  meta:
    description = "datamaliciousorder - file 20160311_d68ea5398722f8b861b4a678324c1881.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3bfaf6a92a2db707860f3468d728ec0b6504324c5d10b8343ef32495fd1d4666"

  strings:
    $s1  = "stored = compilerCache[\"Expan\" + content + \"vironm\".responseContainer() + slow + \"Stri\" + mouseenter](\"%TE\" + bp + \"/\"" ascii
    $s2  = "win = global[\"WScrip\".responseContainer() + configurable][\"Creat\" + not + \"jec\" + configurable](\"MSXML2\".responseContain" ascii
    $s3  = "done[\"R\" + preDispatch + \"n\"](stored.responseContainer((Math.pow((dir / 7), source) - (366 + timerId))), ((1 + -clone) | (14" ascii
    $s4  = "done[\"R\" + preDispatch + \"n\"](stored.responseContainer((Math.pow((dir / 7), source) - (366 + timerId))), ((1 + -clone) | (14" ascii
    $s5  = "rializeArray & 3)) * (source * 3 * serializeArray * 2 / (defaultDisplay - 30)) + ((updateFunc / 32), (source + 0)))) | (contains" ascii
    $s6  = "iner() + _jQuery + \"ika.pl\" + resolve + \"7g5\", !((((((disabled / 23) - (visibility - 77)) + ((ontype / 17) & clone)) & ((3 &" ascii
    $s7  = "stored = compilerCache[\"Expan\" + content + \"vironm\".responseContainer() + slow + \"Stri\" + mouseenter](\"%TE\" + bp + \"/\"" ascii
    $s8  = "win = global[\"WScrip\".responseContainer() + configurable][\"Creat\" + not + \"jec\" + configurable](\"MSXML2\".responseContain" ascii
    $s9  = "content = \"dEn\";" fullword ascii
    $s10 = "return onerror" fullword ascii
    $s11 = "global = (((2063 * source + 299) / (sibling & 15)), ((clone * 3) + (contains / 49)), eval(\"t\" + uniqueSort + \"i\".responseCon" ascii
    $s12 = "ol)), ((0 & clone) / 2 * documentIsHTML));" fullword ascii
    $s13 = "selected = global[insertBefore + \"ript\"][idx + \"ate\".responseContainer() + attrHooks + \"t\"](ajax + \"B.Stre\" + specified)" ascii
    $s14 = "acceptData = global[\"WScr\" + style];" fullword ascii
    $s15 = "selected[td + \"ToF\".responseContainer() + initial](stored, (2 & source));" fullword ascii
    $s16 = "selected[\"op\".responseContainer() + mapped]();" fullword ascii
    $s17 = "win[toggleClass + \"p\" + removeData + \"n\".responseContainer()](all + \"T\", len + \"//per\" + rcheckableType + \"lice.r\".res" ascii
    $s18 = "var onerror = this;" fullword ascii
    $s19 = "function modified() {" fullword ascii
    $s20 = "function curCSSTop() {" fullword ascii

  condition:
    uint16(0) == 0x6474 and
    8 of them
}