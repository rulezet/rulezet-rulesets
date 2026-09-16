import "hash"
rule IOC_FORMBOOK___exe_ {
  meta:
    author     = "Laboratoire Epidemiology & Signal Intelligence"
    ref_IOC    = "IOC_FORMBOOK_LAB"
    date_IOC   = "2023-11-15 07:39:10"
    info       = "Version 1.0 b"
    internal   = false
    score      = 99
    risk_score = 10
    threat     = "FORMBOOK"
    file_type  = "__exe_"
    comment    = "Source : abuse.ch"

  condition:
    hash.sha256(0, filesize) == "a0a6a1c54775713ad3e884b6bc49f2c74f393464a69175c8713221504ae6d72a" or
    hash.sha256(0, filesize) == "cf33cf1b99aec2e58ebff495b327734f9d444884af6846ea086c210bd4ee2623" or
    hash.sha256(0, filesize) == "831abc8d1a70104ae46b5c2c1ce6fce24ef449a03bde0d770a5a67f96ab22e7c"
}