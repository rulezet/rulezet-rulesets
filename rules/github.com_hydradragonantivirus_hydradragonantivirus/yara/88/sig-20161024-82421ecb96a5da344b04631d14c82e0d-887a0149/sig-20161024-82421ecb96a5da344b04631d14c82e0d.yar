rule sig_20161024_82421ecb96a5da344b04631d14c82e0d {
  meta:
    description = "datamaliciousorder - file 20161024_82421ecb96a5da344b04631d14c82e0d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "203619876cff8e29035cc9fb45238f3a7e3e26fe71f87657f243e333ace16b3e"

  strings:
    $s1 = "} while (hw++ < ih);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}