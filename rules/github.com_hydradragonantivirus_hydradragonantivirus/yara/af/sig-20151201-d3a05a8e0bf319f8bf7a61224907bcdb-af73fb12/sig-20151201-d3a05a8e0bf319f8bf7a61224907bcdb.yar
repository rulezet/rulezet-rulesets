rule sig_20151201_d3a05a8e0bf319f8bf7a61224907bcdb {
  meta:
    description = "datamaliciousorder - file 20151201_d3a05a8e0bf319f8bf7a61224907bcdb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "965aa30eda5b981741a4016f03e28d14f1bcc6f279f5b6614193f8b361beeaf2"

  strings:
    $s1  = "var pADYABLrvEaJg = \"%TEMP%\\\\\";" fullword ascii
    $s2  = "cHRegmXPzOSpiF.onreadystatechange = function ()" fullword ascii
    $s3  = "with(AcrwBAQLGzpOE(\"ADOD\" + KcDWBWfcvGalD))" fullword ascii
    $s4  = "cHRegmXPzOSpiF.open(/*s417881nM207022eOZ*/\"G\" + (3884346, /*s661355nM29867eOZ*/ 4879543, /*dca823742zYtzkrxTK717904IlaIWQJrHGj" ascii
    $s5  = "type = 1;" fullword ascii
    $s6  = "open();" fullword ascii
    $s7  = "spaYaT = function (BTAtHeHdLXu, cSrZHOXMZsExiz, KRzpnZlCPqR) {" fullword ascii
    $s8  = "return cSrZHOXMZsExiz;" fullword ascii
    $s9  = "while (ITgfBb) {zHAiGRg}" fullword ascii
    $s10 = "})(this)/*271345304137535853651493670974*/" fullword ascii
    $s11 = "var ITgfBb = true, KcDWBWfcvGalD = (\"B.St\"+(654035, \"ream\"));" fullword ascii
    $s12 = "if (((new Date())>0,2998))" fullword ascii
    $s13 = "(function (nIqktDBBKIhGHi) {" fullword ascii
    $s14 = "function AcrwBAQLGzpOE(vQxaqCMhLbwm) " fullword ascii
    $s15 = "ITgfBb = false; " fullword ascii
    $s16 = "write(cHRegmXPzOSpiF.ResponseBody);" fullword ascii
    $s17 = "return new nIqktDBBKIhGHi.ActiveXObject(vQxaqCMhLbwm)" fullword ascii
    $s18 = "XIjNQmXamgjYPW*/ \"ET\" /*dcazYtzkrx803876TKIlaIWQJr553676HGjLqXIjNQmX121375amgjYPW*/), BTAtHeHdLXu, false);" fullword ascii

  condition:
    uint16(0) == 0x6628 and
    8 of them
}