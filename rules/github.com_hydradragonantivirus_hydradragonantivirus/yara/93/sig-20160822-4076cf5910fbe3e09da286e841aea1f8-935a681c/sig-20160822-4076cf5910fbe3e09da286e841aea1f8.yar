rule sig_20160822_4076cf5910fbe3e09da286e841aea1f8 {
  meta:
    description = "datamaliciousorder - file 20160822_4076cf5910fbe3e09da286e841aea1f8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0619a5d5c1f8eef18eb44b610f9e9db61b573a6035a6801ffecf2cfdd6eeb302"

  strings:
    $s1 = "var Cp = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74\"" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}