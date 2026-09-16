rule sig_20160314_6621ab7cb27b3dea3a2897ef9941ca6d {
  meta:
    description = "datamaliciousorder - file 20160314_6621ab7cb27b3dea3a2897ef9941ca6d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "95070a26e6dc9c975d92f268d782d20bd5a6f20a57a312bae8ce765cc85c2472"

  strings:
    $s1 = "while (QJLufHkAgJjCWhU.readystate < 4 ) {WScript.Sleep(1000)};" fullword ascii
    $s2 = "QJLufHkAgJjCWhU.open(zvITFE + IGCUg, ikCuCfGlEaI + eFuCVmptRmraFgy + znaLKcNsjvwUzFN + iiuRb + ZqkbtVBNSUrv + YZNYxrPVbi + xWSiA" ascii
    $s3 = "function KztaU(fname)" fullword ascii
    $s4 = "+ UDuokPoaPCA + acGdlylGPZQXRZ + ERuDdSQOv + BnFwKc + GpJay, false);" fullword ascii
    $s5 = "function JOqJsnbSSTl(n)" fullword ascii
    $s6 = "var wFmXen = new Date();" fullword ascii
    $s7 = "return qyxW + jHOpWLlHvJ + NenhcmmEqzFz + MQyEAV + kZUUiJDntlITQSv + zlJcAdtrN + fdiNxKCZHDhwUr" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}