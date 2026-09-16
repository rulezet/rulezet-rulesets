import "hash"
rule IOC_COINMINER_msi {
  meta:
    author     = "Laboratoire Epidemiology & Signal Intelligence"
    ref_IOC    = "IOC_COINMINER_LAB"
    date_IOC   = "2023-11-14 18:22:54"
    info       = "Version 1.0 b"
    internal   = false
    score      = 99
    risk_score = 10
    threat     = "COINMINER"
    file_type  = "msi"
    comment    = "Source : abuse.ch"

  condition:
    hash.sha256(0, filesize) == "c29a303468ce5c3274902765deac7a76d4fa98c10657be06acd7d1a358341c93" or
    hash.sha256(0, filesize) == "ca4a43510da2087936b6a7aa6790d506f4aba6b1ff1f1d9fcc8fcba37fb47749" or
    hash.sha256(0, filesize) == "831abc8d1a70104ae46b5c2c1ce6fce24ef449a03bde0d770a5a67f96ab22e7c"
}