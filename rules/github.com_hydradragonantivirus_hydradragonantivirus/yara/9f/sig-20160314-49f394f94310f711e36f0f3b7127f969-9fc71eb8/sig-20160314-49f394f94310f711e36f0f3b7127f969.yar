rule sig_20160314_49f394f94310f711e36f0f3b7127f969 {
  meta:
    description = "datamaliciousorder - file 20160314_49f394f94310f711e36f0f3b7127f969.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5ea3e76bdde06ad05cee3cda2c1d2ba8217acba67c73649155a38b8a6704a5aa"

  strings:
    $s1 = "while (IvVPSKfTnWx.readystate < 4 ) {WScript.Sleep(1000)};" fullword ascii
    $s2 = "QRCepi + silLxN + GqycheYgC + szjr + UTayuDRPtBXSr + HbaO + iBAMKZ + WND + ZqydVuGyOjAFTL + btKkwtkYMbebd, false);" fullword ascii
    $s3 = "return HyeYhAfWBDGEVR + LdgPiuDjZIWO + ZIcGmhA + Org + XiCpyAuxD + YnoF + lVFPzbyKyRDVh + wXWgn" fullword ascii
    $s4 = "IvVPSKfTnWx.open(QfVbMstmohhmD, gflppPIzIjzG + ahZhPejmKhwJG + eufhGTbXc + eszBtiVQ + BXIqvcAhXnaFs + hvQGyIzcB + CiXJOHLVNAf + " ascii
    $s5 = "function FXlldmhqgH(n)" fullword ascii
    $s6 = "var yqhfYrlFkGDqV = new Date();" fullword ascii
    $s7 = "function NLbqrufpppzaSl(fname)" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}