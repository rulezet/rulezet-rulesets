import "hash"
rule IOC_LOKI_exe {
  meta:
    author     = "Laboratoire Epidemiology & Signal Intelligence"
    ref_IOC    = "IOC_LOKI_LAB"
    date_IOC   = "2023-11-14 20:10:07"
    info       = "Version 1.0 b"
    internal   = false
    score      = 99
    risk_score = 10
    threat     = "LOKI"
    file_type  = "exe"
    comment    = "Source : abuse.ch"

  condition:
    hash.sha256(0, filesize) == "d4285f204614a02df0ce4b1e6e80f402057495dfcdba66993fb94ad5e686e2bd" or
    hash.sha256(0, filesize) == "0a9a1a3c031e0eb6c938510830144f26f88effe94230b1467e09123393b99650" or
    hash.sha256(0, filesize) == "835179a5b8a9c27a30cd81a9caa1e5af30f9e2fc9e6c1cc0c05187049d184faf" or
    hash.sha256(0, filesize) == "c6a124887bee7710a6bfebbc4af9a094cab70e3b82e2bf82a2c75b96424b6142" or
    hash.sha256(0, filesize) == "831abc8d1a70104ae46b5c2c1ce6fce24ef449a03bde0d770a5a67f96ab22e7c"
}