rule sig_20161024_3940ed050a27e19351bd6a8da9f793f9 {
  meta:
    description = "datamaliciousorder - file 20161024_3940ed050a27e19351bd6a8da9f793f9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b1e16304066fe4da8bee8f5e6cf5b67f07c76559ccebfe475701be9083e65a84"

  strings:
    $s1 = "} while (eh++ < wb);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}