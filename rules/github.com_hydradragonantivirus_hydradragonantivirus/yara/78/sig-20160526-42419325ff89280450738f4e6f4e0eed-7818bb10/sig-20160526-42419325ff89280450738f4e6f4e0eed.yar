rule sig_20160526_42419325ff89280450738f4e6f4e0eed {
  meta:
    description = "datamaliciousorder - file 20160526_42419325ff89280450738f4e6f4e0eed.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a2915e7921d5b9c0a42e77cf24531322818df6f82282913e910a4abab44ac222"

  strings:
    $s1 = "64x\\\\o\" = m4uGAUKLN rav\\n;\"ec6x\\\\\" = v6vOOZYED rav\\n;\"f6x\\\\lc\" = w9jJAFDOR rav\\n;\"56x\\\\s\" = b4vPCCNHP rav'[\"s" ascii

  condition:
    uint16(0) == 0x200a and
    all of them
}