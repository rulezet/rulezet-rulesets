rule OpenSSL_DSAgen__8_byt_19_ {
  strings:
    $a0 = { d5 01 4e 4b 60 ef 2b a8 b6 21 1b 40 62 ba 32 24 e0 42 7d }

  condition:
    $a0
}