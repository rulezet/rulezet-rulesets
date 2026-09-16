import "hash"
rule IOC_DCRAT_exe {
  meta:
    author     = "Laboratoire Epidemiology & Signal Intelligence"
    ref_IOC    = "IOC_DCRAT_LAB"
    date_IOC   = "2023-11-14 12:45:44"
    info       = "Version 1.0 b"
    internal   = false
    score      = 99
    risk_score = 10
    threat     = "DCRAT"
    file_type  = "exe"
    comment    = "Source : abuse.ch"

  condition:
    hash.sha256(0, filesize) == "07fa9ac4502b2a0ba83036450abbe28d6656c8941abf5180e81650550aa50a4e" or
    hash.sha256(0, filesize) == "b84309a3904c7956ca30b8803e41862ab7b4de1dd943f57ce5a211f2479e48c4" or
    hash.sha256(0, filesize) == "831abc8d1a70104ae46b5c2c1ce6fce24ef449a03bde0d770a5a67f96ab22e7c"
}