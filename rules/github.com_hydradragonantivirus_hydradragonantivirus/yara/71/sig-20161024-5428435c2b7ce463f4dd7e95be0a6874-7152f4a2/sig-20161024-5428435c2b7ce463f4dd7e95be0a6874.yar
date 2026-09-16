rule sig_20161024_5428435c2b7ce463f4dd7e95be0a6874 {
  meta:
    description = "datamaliciousorder - file 20161024_5428435c2b7ce463f4dd7e95be0a6874.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "31e15bc15fd4118d8373da7ecbe7fdecdff7f7e12b6449d37ab598adcecae46d"

  strings:
    $s1 = "} while (gr++ < ee);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}