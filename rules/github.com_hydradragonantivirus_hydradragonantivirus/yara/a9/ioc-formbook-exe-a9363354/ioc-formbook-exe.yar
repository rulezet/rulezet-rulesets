import "hash"
rule IOC_FORMBOOK_exe {
  meta:
    author     = "Laboratoire Epidemiology & Signal Intelligence"
    ref_IOC    = "IOC_FORMBOOK_LAB"
    date_IOC   = "2023-11-14 05:40:06"
    info       = "Version 1.0 b"
    internal   = false
    score      = 99
    risk_score = 10
    threat     = "FORMBOOK"
    file_type  = "exe"
    comment    = "Source : abuse.ch"

  condition:
    hash.sha256(0, filesize) == "10f863afc82cd61fdc8a55bc67e2726401ac51c4e9647ddd19dbf1ea30df9e09" or
    hash.sha256(0, filesize) == "c88aa06f7f7d22f3a6c66c84bf6aafd8838357d02d2287bbbcd61fb21264dfe4" or
    hash.sha256(0, filesize) == "0838dcd24cf228707272c365f4a9552e4d3b69b43716cea36fd95f250f62a7ab" or
    hash.sha256(0, filesize) == "6282a84266a87aa1e62b1304913bfdc8ce4c122f59f5731503f78655beaaa27e" or
    hash.sha256(0, filesize) == "d2799bffc4e285fb9472cdf9e68b4637288c44cd7ed7d5ff7680228c63d525b7" or
    hash.sha256(0, filesize) == "f93737e8575d0af497e1432588bea5d62c86f7984605af2c257002b73563d0f8" or
    hash.sha256(0, filesize) == "1263a6f6ffb8706a7785cc11b08c4a9c6609a3823ca758dbc4777b4639ebd2a8" or
    hash.sha256(0, filesize) == "a3e4cc3747006495c9cae3e6f08010b8368ebd5883b556e021a923fc20f5bef1" or
    hash.sha256(0, filesize) == "de370b8f6e1ebb2f43c5fb9ac7392cc5c70224f10c31bdad38cf369744d03d52" or
    hash.sha256(0, filesize) == "03ff02d6d7a259734c8733614089ac81324a837102a6ae3484491cfe7eed975f" or
    hash.sha256(0, filesize) == "831abc8d1a70104ae46b5c2c1ce6fce24ef449a03bde0d770a5a67f96ab22e7c"
}