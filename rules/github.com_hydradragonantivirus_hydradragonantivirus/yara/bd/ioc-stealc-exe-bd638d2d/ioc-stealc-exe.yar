import "hash"
rule IOC_STEALC_exe {
  meta:
    author     = "Laboratoire Epidemiology & Signal Intelligence"
    ref_IOC    = "IOC_STEALC_LAB"
    date_IOC   = "2023-11-14 08:09:03"
    info       = "Version 1.0 b"
    internal   = false
    score      = 99
    risk_score = 10
    threat     = "STEALC"
    file_type  = "exe"
    comment    = "Source : abuse.ch"

  condition:
    hash.sha256(0, filesize) == "18db81d906e97ea89314ddaa87811b43e349e08a2af276dcfe21f3031131e69f" or
    hash.sha256(0, filesize) == "0552f23284ed52e84060cdc66d242f9258bbe0555eab899355b9d848bbf70605" or
    hash.sha256(0, filesize) == "60e9383ff5038ed988a1b988b66091bac7bf93a6d070763f45479dccdfd9d147" or
    hash.sha256(0, filesize) == "831abc8d1a70104ae46b5c2c1ce6fce24ef449a03bde0d770a5a67f96ab22e7c"
}