import "hash"
rule IOC_NA_7z {
  meta:
    author     = "Laboratoire Epidemiology & Signal Intelligence"
    ref_IOC    = "IOC_NA_LAB"
    date_IOC   = "2023-11-15 19:09:26"
    info       = "Version 1.0 b"
    internal   = false
    score      = 99
    risk_score = 10
    threat     = "NA"
    file_type  = "7z"
    comment    = "Source : abuse.ch"

  condition:
    hash.sha256(0, filesize) == "23c1510d3d22c30ed9ef184edf9f2e078906915b5e37e67b023230b8cd60403f" or
    hash.sha256(0, filesize) == "f52747475852e8cf7e34f28be8946365d35d52a8d2b5339ec8ce9a302a4bf049" or
    hash.sha256(0, filesize) == "831abc8d1a70104ae46b5c2c1ce6fce24ef449a03bde0d770a5a67f96ab22e7c"
}