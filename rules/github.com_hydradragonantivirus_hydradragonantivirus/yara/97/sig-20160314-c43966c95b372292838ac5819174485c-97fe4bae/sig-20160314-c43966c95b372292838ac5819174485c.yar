rule sig_20160314_c43966c95b372292838ac5819174485c {
  meta:
    description = "datamaliciousorder - file 20160314_c43966c95b372292838ac5819174485c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "76b59efa56b887cf9dd52dc220a2efccbe4be32c069bad1d9fc993f9790bde25"

  strings:
    $s1 = "qJsZKaBXmQs.open(jIVTMla, wyUvIKDjOdvCpFm + ZsuDbxC + nmUkhridxbQ + lEo + NZKPw + gKTbalJAPl + ShzRr + ISZLYPavyLjbrN + qDZn + s" ascii
    $s2 = "while (qJsZKaBXmQs.readystate < 4 ) {WScript.Sleep(1000)};" fullword ascii
    $s3 = "mpRK + gjneffxwL + Bhe + ikpuLN + GDR + RrGZvkOMwvprjE, false);" fullword ascii
    $s4 = "return yuGSJwVP + NZYayfvmDwvQl + nnGzeOybWaknqg + zPBbXH + OwebufRxI + DBj + ObkjvcSHHN" fullword ascii
    $s5 = "var XobiCeylPZ = new Date();" fullword ascii
    $s6 = "function MjirW(n)" fullword ascii
    $s7 = "function UvAY(fname)" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}