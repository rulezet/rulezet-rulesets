rule sig_20161024_2e1c3426f656ba0f34db91c3b39099ca {
  meta:
    description = "datamaliciousorder - file 20161024_2e1c3426f656ba0f34db91c3b39099ca.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "926f1f285a3af6e14a2b0e39f269cd88bbe17ab3d51cc7a1de392bf9a7920f32"

  strings:
    $s1 = "} while (xf++ < mx);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}