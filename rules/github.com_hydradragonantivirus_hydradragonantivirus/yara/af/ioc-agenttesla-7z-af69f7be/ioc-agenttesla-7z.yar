import "hash"
rule IOC_AGENTTESLA_7z {
  meta:
    author     = "Laboratoire Epidemiology & Signal Intelligence"
    ref_IOC    = "IOC_AGENTTESLA_LAB"
    date_IOC   = "2023-11-14 08:08:31"
    info       = "Version 1.0 b"
    internal   = false
    score      = 99
    risk_score = 10
    threat     = "AGENTTESLA"
    file_type  = "7z"
    comment    = "Source : abuse.ch"

  condition:
    hash.sha256(0, filesize) == "04a69ab46c2e8bbdb13a2da0516d6caad98637405e6f7c580c18cd46b3b8094f" or
    hash.sha256(0, filesize) == "42296e0960cd2bebfb412cfe15f7bdf9f8d0fe2587afc0d09fb1f8655a273a87" or
    hash.sha256(0, filesize) == "458f3af48bcb01ad84a623f56afa02b5bc4758b6e4b7c0c3cd1e0224254b1302" or
    hash.sha256(0, filesize) == "99d376b4afcda6983c0030431b264aaedcfc09d7b805fe0d3c372175695da8a8" or
    hash.sha256(0, filesize) == "caeb162a67c1946c9234161ea37cc50fa5956fce5a3296ef36b7f9a6ba68f889" or
    hash.sha256(0, filesize) == "6d833846ce0ffab7ee3c9f8872fc99e9a06ce8fa0cbcbeb039c00ba209256116" or
    hash.sha256(0, filesize) == "831abc8d1a70104ae46b5c2c1ce6fce24ef449a03bde0d770a5a67f96ab22e7c"
}