import "hash"
rule IOC_NA_msi {
  meta:
    author     = "Laboratoire Epidemiology & Signal Intelligence"
    ref_IOC    = "IOC_NA_LAB"
    date_IOC   = "2023-11-14 06:30:05"
    info       = "Version 1.0 b"
    internal   = false
    score      = 99
    risk_score = 10
    threat     = "NA"
    file_type  = "msi"
    comment    = "Source : abuse.ch"

  condition:
    hash.sha256(0, filesize) == "d82ea0bf95437276d3c5bc8f78b6f3ca21e028ec69e3c0ec15bdca37badcbef6" or
    hash.sha256(0, filesize) == "a8338b8fece4e078c2ec6b634d6d1a161beb68cc8632e41127edb24e2b9ec80c" or
    hash.sha256(0, filesize) == "70ae0ba7881ccde62370f1168b00662af52a354b97f6cf8b01219f9046c0270f" or
    hash.sha256(0, filesize) == "ab6b3a30d643bd1a807d4415e554a7e005c9320d1adbd0bfb4666cf1509c3078" or
    hash.sha256(0, filesize) == "69925c370a71b0bc37eb5d6381e8fc3309a7e71a7bdade54233214c73c728170" or
    hash.sha256(0, filesize) == "24e7e2dcb6102224d489081a32b1aee6c1ea035295d58fbce7f85c7f22c543fe" or
    hash.sha256(0, filesize) == "831abc8d1a70104ae46b5c2c1ce6fce24ef449a03bde0d770a5a67f96ab22e7c"
}