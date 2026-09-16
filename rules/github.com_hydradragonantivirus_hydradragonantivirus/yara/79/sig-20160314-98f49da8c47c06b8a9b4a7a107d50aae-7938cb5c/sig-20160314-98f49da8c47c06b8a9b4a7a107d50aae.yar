rule sig_20160314_98f49da8c47c06b8a9b4a7a107d50aae {
  meta:
    description = "datamaliciousorder - file 20160314_98f49da8c47c06b8a9b4a7a107d50aae.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "aa7b7cb112eb818f130d3a63f83288e772390d039d7343dd0e5b9174cc187df0"

  strings:
    $s1 = "MgDDJ.open(JrBOdrwxipeC, tQwWnPap + dvOyCIh + kWjuKlFgussMJSS + DSCTPgt + GdofpeVN + wFBDh + JCvzUYSTZDpi + IXJjcRSMNQWaHo + Dvf" ascii
    $s2 = "while (MgDDJ.readystate < 4 ) {WScript.Sleep(1000)};" fullword ascii
    $s3 = "hFgybMb + IRuJZs + cupl + VGkYwutAC + NwECtEmA + PCGWJPZubhHDGm + oTvZqWzLtKWUIB, false);" fullword ascii
    $s4 = "return APhMSco + tbVJ + ZpIhwefj + HXUlyxxXgK + OjZTgpeSVwHm + ABaUSAJzUxLhyD + XwUFsKDJMGrFVmT + fAQ + bWWJpaYCurwEBw + jHjLpQZ" ascii
    $s5 = "function VqHt(n)" fullword ascii
    $s6 = "function LJUWDrKuQVxMR(fname)" fullword ascii
    $s7 = "var CyauTDSnuZbnF = new Date();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}