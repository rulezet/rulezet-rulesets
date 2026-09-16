rule sig_20160824_59ce2ee7c4d8503963235dc660563f61 {
  meta:
    description = "datamaliciousorder - file 20160824_59ce2ee7c4d8503963235dc660563f61.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a576064d84e3b5d73bea43368e27e3ba5aa09cd718282e1aa57e912fec288b8f"

  strings:
    $s1 = "var Nt0 = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}