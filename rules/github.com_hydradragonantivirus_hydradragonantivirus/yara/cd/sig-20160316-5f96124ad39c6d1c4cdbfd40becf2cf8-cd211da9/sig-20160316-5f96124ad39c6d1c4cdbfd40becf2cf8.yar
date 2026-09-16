rule sig_20160316_5f96124ad39c6d1c4cdbfd40becf2cf8 {
  meta:
    description = "datamaliciousorder - file 20160316_5f96124ad39c6d1c4cdbfd40becf2cf8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3796f807cfbf5a538e48cbf0d51687e859710267bedd12fdae555e0aea52d9d2"

  strings:
    $s1 = "while (QQqOy[AVqiqOFgMHUcIqX + ODMdbd + atXK + SONNA + VRItWdiatX] < 4 ) {WScript[LqiEBdrKqiVWfk + pnR + WKDLsBkKvrx](1000)};" fullword ascii
    $s2 = "QQqOy[PHH + WpyxeyMEhpeLDhk + YddVkYywIvz](CGgrJdISkTKhVFI + vtekSXezU, QrcdfoutLbU + oxt + hXDDpmzv + KuMHd + rmwE + gjqtfvRIqy" ascii
    $s3 = "GlHOK + tsjafMMvexpI + cDa + qwE + GtLZx + QLZqvUoLtqoUMj + cXqwlgSWVHdEEm, false);" fullword ascii
    $s4 = "function IDRrHxbyBl(n){return deLgXQP + iBTdsXXwHrWoFQ + TXmyQawFYenuIdv + xBL + IuKqOMs + QctVuV + jWaz;}" fullword ascii
    $s5 = "function EYtBPo(KlEpU){fyi[bFBrgLx + biclNLIaSXeVl](KlEpU, 0, 0);}" fullword ascii
    $s6 = "var YRrXzwXRjGcpZA = new Date();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}