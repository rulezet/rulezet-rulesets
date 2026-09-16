rule sig_20160314_75496ea13d21fd6efdabc9b15cd4d6f2 {
  meta:
    description = "datamaliciousorder - file 20160314_75496ea13d21fd6efdabc9b15cd4d6f2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c25585ae00f63f41b69c8c40328fd0c38cadaea90554a093cd8e2e558f830ac6"

  strings:
    $s1 = "gvjfmPW.open(LDYLJF, RgvLMHduB + tVdVh + pdoIYt + AJf + TMLXJdJDswFNKk + EbAUQNOBFS + EZXSE + KTMj + jnwjaKjaHQdqWb + NUar + iYU" ascii
    $s2 = "while (gvjfmPW.readystate < 4 ) {WScript.Sleep(1000)};" fullword ascii
    $s3 = "return llnLrSCy + CWIVlr + qwzqGgUSLN + QGDB + ibArNMZaMxjYeK + OOlg + zZmjHhv + XdueP" fullword ascii
    $s4 = "RmYedGaAAb + KjLAuiskPOGXnbe + IpkAXJEeiBk + thaRtEpOwFqQc + NZVgdxCt, false);" fullword ascii
    $s5 = "function JduG(n)" fullword ascii
    $s6 = "var ilTe = new Date();" fullword ascii
    $s7 = "function dNK(fname)" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}