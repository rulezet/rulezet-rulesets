rule TTP_XOR_MULT_DOSStub_621a {
  strings:
    $key_621a = { 36 72 [2] 42 6a [2] 05 68 [2] 42 79 [2] 0c 75 [2] 00 7f [2] 17 74 [2] 0c 3a [2] 31 }

  condition:
    any of them
}