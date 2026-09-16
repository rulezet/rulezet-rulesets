rule TTP_XOR_MULT_DOSStub_144a {
  strings:
    $key_144a = { 40 22 [2] 34 3a [2] 73 38 [2] 34 29 [2] 7a 25 [2] 76 2f [2] 61 24 [2] 7a 6a [2] 47 }

  condition:
    any of them
}