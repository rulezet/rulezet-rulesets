rule sig_20160315_ffd17a6f175ea11a8267f0f41db4ddd6 {
  meta:
    description = "datamaliciousorder - file 20160315_ffd17a6f175ea11a8267f0f41db4ddd6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1ac4094a68dae39b9a9f55b7d25f0f7cfbfdbef93ac5572d59fe8c2c7fee7427"

  strings:
    $s1 = "while (Bmgc.readystate < 4 ) {WScript.Sleep(1000)};" fullword ascii
    $s2 = "function LBkU(oZPtBEhMLmnEHb){WshShell[EgCNDkaIIS](oZPtBEhMLmnEHb, 0, 0);}" fullword ascii
    $s3 = " + apu + UJguAtp + JuYr + PWlDHQnBAePGy + qbkozOmzAR + JsAdrCyKRXMLBv + cwlwTXrsnHMt, false);" fullword ascii
    $s4 = "function vkyQJyeemfnN(n){return BoMDVkTVkxaRLAm + XyPCKrWEm + iMXqcMY + GpPHUzZMvhaRE + qaWHi + YbyJgB;}" fullword ascii
    $s5 = "Bmgc[coEkwDlY + sbXAJKpE](rbocAeN + FhyhIwshvDXmqv + FtyJIasWYToy, ehPc + xjspJrp + nxOZT + GaGGZcIYsNv + oNXxCfLL + ECMDEAkqTJl" ascii
    $s6 = "var msJBLKbgocM = new Date();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}