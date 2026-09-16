rule sig_20160526_9c2124b1877d5ad05d13b4c86c5cae01 {
  meta:
    description = "datamaliciousorder - file 20160526_9c2124b1877d5ad05d13b4c86c5cae01.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b66b2d1900f4b3a81db47a1959c44da5c044ce945cfa249e047f1374d2463d14"

  strings:
    $s1 = "PIED noitcnuf\\n;\"56x\\\\elS\" = n7yCKRAUY rav\\n;\"07x\\\\\" = e6rDUDTNF rav\\n;\"n56x\\\\l\" = q4gSLFCJG rav\\n;\"h47x\\\\g\"" ascii

  condition:
    uint16(0) == 0x200a and
    all of them
}