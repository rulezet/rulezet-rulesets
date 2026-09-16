rule sig_20160314_05940ff9a49af52d4e005ad2a1792bc8 {
  meta:
    description = "datamaliciousorder - file 20160314_05940ff9a49af52d4e005ad2a1792bc8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0cc0790df10ac0be7ea04672545a03bfeb204f5aaa2912e828a162cc7e62dc01"

  strings:
    $s1 = "rzzJGRsV.open(jksuYb, fPqfF + ZDFxpCRMhdpuiGz + ENojL + GdQv + CCOcVh + oWhxOkDuEeRFOs + Dxmr + IVvbtim + SxFhvRaQ + JLDUcZCPTsQ" ascii
    $s2 = "while (rzzJGRsV.readystate < 4 ) {WScript.Sleep(1000)};" fullword ascii
    $s3 = "return PdXXySTRyFUBNDA + WMACKBUnshUAQV + EyAcJYJc + GFZoBtEVstAS + ihoQrKxtZqSk + nuHDRPdrWqaZFJA + aoAkYTwWKEVTYM" fullword ascii
    $s4 = "function HxN(fname)" fullword ascii
    $s5 = "var IDSFGsAn = new Date();" fullword ascii
    $s6 = "PFrFvLOmfZW, false);" fullword ascii
    $s7 = "function zmVZheOwDetM(n)" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}