rule TTP_XOR_MULT_DOSStub_740a {
  strings:
    $key_740a = { 20 62 [2] 54 7a [2] 13 78 [2] 54 69 [2] 1a 65 [2] 16 6f [2] 01 64 [2] 1a 2a [2] 27 }

  condition:
    any of them
}