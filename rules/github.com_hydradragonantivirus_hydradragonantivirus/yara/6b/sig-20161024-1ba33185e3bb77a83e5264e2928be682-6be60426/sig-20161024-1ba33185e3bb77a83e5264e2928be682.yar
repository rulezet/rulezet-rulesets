rule sig_20161024_1ba33185e3bb77a83e5264e2928be682 {
  meta:
    description = "datamaliciousorder - file 20161024_1ba33185e3bb77a83e5264e2928be682.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0321c87712e23baa4d13bf946975e1534a0c7ce9dde981d616a81dc13b81ada1"

  strings:
    $s1 = "} while (xq++ < wq);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}