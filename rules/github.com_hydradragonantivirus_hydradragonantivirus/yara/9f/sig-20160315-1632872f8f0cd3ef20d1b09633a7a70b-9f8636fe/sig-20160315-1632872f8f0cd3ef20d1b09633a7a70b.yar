rule sig_20160315_1632872f8f0cd3ef20d1b09633a7a70b {
  meta:
    description = "datamaliciousorder - file 20160315_1632872f8f0cd3ef20d1b09633a7a70b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5909c0a62465af0e1b8b00c1b8cf56511e3805e5cbf0964054109c13496c684e"

  strings:
    $s1 = "while (SxCVEB.readystate < 4 ) {WScript.Sleep(1000)};" fullword ascii
    $s2 = "function VlZnH(EGeJF){WshShell[ehtcUqZU](EGeJF, 0, 0);}" fullword ascii
    $s3 = "SxCVEB[QFNqIDFbGiAqsn + zbHZ](ZifYehqyKxy + yZtDveSenBrbXE, LrvCXevSfnI + eoZLQyPzbtyAv + UOCETkZKUsH + MoINqwjpQJnrlZ + mvuAEwv" ascii
    $s4 = "qjnNSTUIyOXYh[ZYpiTOi + HEAt] = 1;" fullword ascii
    $s5 = "sAxCthIZL + QmiOGWvGQ + ZfcqdxJ + DGn + RfrINy + UiVnXbWpBRzlrF + kWaruEGQ + tcsbuIKGOZsaSw + zGYmNDVR, false);" fullword ascii
    $s6 = "function crlZBDwagfq(n){return CFazJt + VRk + BZeZaNoSHIrWXGM + egU + osNjbKYscebpVdC + LavWCVlTQwVtA + oFfHyGZNeSC + SGyXoogHaS" ascii
    $s7 = "var HEAt = \"e\";" fullword ascii
    $s8 = "var KwRCTiQV = new Date();" fullword ascii
    $s9 = "function crlZBDwagfq(n){return CFazJt + VRk + BZeZaNoSHIrWXGM + egU + osNjbKYscebpVdC + LavWCVlTQwVtA + oFfHyGZNeSC + SGyXoogHaS" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}