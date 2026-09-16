rule sig_20170214_4a3538f87826db48fe9f55f7f6c82a51 {
  meta:
    description = "datamaliciousorder - file 20170214_4a3538f87826db48fe9f55f7f6c82a51.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "aeeefca0a411019d493061d9eefe5d5a8fda185988bba4b008f08948ddd0f99c"

  strings:
    $s1  = "var mist = [String, WScript, String, String, String, String, String, String, String, String, String, String][1][nloci + ylkozy +" ascii
    $s2  = "var tbotpy = [String, WScript, String, String, String, String, String, String, String, String, String, String][1][nloci + ylkozy" ascii
    $s3  = "var tbotpy = [String, WScript, String, String, String, String, String, String, String, String, String, String][1][nloci + ylkozy" ascii
    $s4  = "var mist = [String, WScript, String, String, String, String, String, String, String, String, String, String][1][nloci + ylkozy +" ascii
    $s5  = "var opzexd = [String, String, String, String, String, String, String, String, String, \"C:\\\\d\", String][9];" fullword ascii
    $s6  = "var fuqbu = [String, String, String, String, \"GetD\", String, String, String, String, String, String, String][4];" fullword ascii
    $s7  = "var egmevbizx = [String, String, String, String, String, String, String, String, String, String, \"cmd.\", String][10];" fullword ascii
    $s8  = "var vpircen = [\"essi\", String, String, String, String, String, String, String, String, String, String][0];" fullword ascii
    $s9  = "var ologepd = [String, String, String, String, String, String, String, String, \"'^ $\", String, String][8];" fullword ascii
    $s10 = "//if ([String, String, String, String, String, String, String, String, String, String, new[String, String, String, String, Strin" ascii
    $s11 = "ytt + uqsikuhv + vvunju + ckinac + zvofpupo + cetvi + uzjuf + fyfxy + xiby + ugeb + myla + uwhiv + iwofvit + bmydu)(), String][1" ascii
    $s12 = "uxin + orxoqvi + opzexd + vnuxvywb + orxol + fatisu + hihal + bukyp + gatkyw + idjocsy + ohjutpi + agmuke + afaxe + pewy + onihr" ascii
    $s13 = "g, dliqelki, String, String, String, String, String][5](ijlomjejp + vedtak + fuqbu + rnapigse + jespucwu + atobxic + ewugycp + n" ascii
    $s14 = "var orcomc = [String, String, String, String, String, String, \"myv=\", String, String, String, String][6];" fullword ascii
    $s15 = "var vikqe = [String, String, String, String, String, String, String, String, String, String, \"run\"][10];" fullword ascii
    $s16 = "var udtycomd = [\"+$hj\", String, String, String, String, String, String, String, String, String, String][0];" fullword ascii
    $s17 = "var uqsikuhv = [String, String, String, String, String, String, String, String, String, String, \"fs45\", String][10];" fullword ascii
    $s18 = "var ckinac = [String, String, String, String, String, String, String, String, \"sdfs\", String, String][8];" fullword ascii
    $s19 = "var sojo = [String, String, String, String, String, String, \"gqon\", String, String, String, String][6];" fullword ascii
    $s20 = "var yfazv = [String, String, String, String, String, String, String, String, String, \"='^ \", String][9];" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}