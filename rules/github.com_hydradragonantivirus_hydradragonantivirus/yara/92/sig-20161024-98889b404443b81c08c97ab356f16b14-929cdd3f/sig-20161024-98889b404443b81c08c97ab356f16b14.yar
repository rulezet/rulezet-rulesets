rule sig_20161024_98889b404443b81c08c97ab356f16b14 {
  meta:
    description = "datamaliciousorder - file 20161024_98889b404443b81c08c97ab356f16b14.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "62c56a4c306f5dce55b2cec1d0e44aae0a7b542606c1e3cf7cd76f2bc97dfb84"

  strings:
    $s1 = "} while (si++ < fl0);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}