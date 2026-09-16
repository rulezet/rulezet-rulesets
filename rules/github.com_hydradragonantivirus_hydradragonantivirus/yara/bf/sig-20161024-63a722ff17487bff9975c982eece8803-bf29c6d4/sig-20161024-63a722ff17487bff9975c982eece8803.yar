rule sig_20161024_63a722ff17487bff9975c982eece8803 {
  meta:
    description = "datamaliciousorder - file 20161024_63a722ff17487bff9975c982eece8803.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "99738ba4cbfbd760f46258ce3d03c015093671b324e51b9c3af63c8bf3d2afed"

  strings:
    $s1 = "} while (ib0++ < yk);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}