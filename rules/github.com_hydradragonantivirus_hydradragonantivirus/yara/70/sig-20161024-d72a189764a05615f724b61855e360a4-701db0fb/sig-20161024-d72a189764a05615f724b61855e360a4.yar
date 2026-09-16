rule sig_20161024_d72a189764a05615f724b61855e360a4 {
  meta:
    description = "datamaliciousorder - file 20161024_d72a189764a05615f724b61855e360a4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ed833c0716714616a5b6ed3b8f0c1bcf4f2f139bc7ccf8222ec44350843382f1"

  strings:
    $s1 = "} while (rb++ < xu);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}