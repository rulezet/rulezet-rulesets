rule DITEKSHEN_INDICATOR_KB_ID_Ransomware_Alumnilocker {
  meta:
    description = "Detects files referencing identities associated with AlumniLocker ransomware"
    author      = "ditekShen"
    id          = "64b6aff8-3758-5837-b814-e2505a9c12a3"
    date        = "2024-01-23"
    modified    = "2024-01-23"
    reference   = "https://github.com/ditekshen/detection"
    source_url  = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/yara/indicator_knownbad_id.yar#L194-L202"
    license_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/LICENSE.txt"
    logic_hash  = "aeab9cb2b2da246e1863cd1102d901d322017d0b309e852d83e4f66f6e4bdd22"
    score       = 75
    quality     = 73
    tags        = ""

  strings:
    $s1 = "alumnilocker@protonmail.com" ascii wide nocase

  condition:
    any of them
}