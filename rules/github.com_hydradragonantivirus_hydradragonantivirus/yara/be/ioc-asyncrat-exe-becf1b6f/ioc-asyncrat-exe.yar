import "hash"
rule IOC_ASYNCRAT_exe {
  meta:
    author     = "Laboratoire Epidemiology & Signal Intelligence"
    ref_IOC    = "IOC_ASYNCRAT_LAB"
    date_IOC   = "2023-11-14 09:19:43"
    info       = "Version 1.0 b"
    internal   = false
    score      = 99
    risk_score = 10
    threat     = "ASYNCRAT"
    file_type  = "exe"
    comment    = "Source : abuse.ch"

  condition:
    hash.sha256(0, filesize) == "a9b516990db5fb757d5745cbca218fb6996562af0454dc3820403890d77abcb6" or
    hash.sha256(0, filesize) == "ebb3a5afeb6a34fd0ca7e4ee234a04f66de5b7a38fbc4171ff5e8bcaeec8e100" or
    hash.sha256(0, filesize) == "2a318235a7908da2cfacd1711becc3c0da7a23359a98628f6d1fe14a7dd97b70" or
    hash.sha256(0, filesize) == "831abc8d1a70104ae46b5c2c1ce6fce24ef449a03bde0d770a5a67f96ab22e7c"
}