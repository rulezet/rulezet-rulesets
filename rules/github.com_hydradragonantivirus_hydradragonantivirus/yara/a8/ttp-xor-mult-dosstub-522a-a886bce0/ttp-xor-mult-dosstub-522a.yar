rule TTP_XOR_MULT_DOSStub_522a {
  strings:
    $key_522a = { 06 42 [2] 72 5a [2] 35 58 [2] 72 49 [2] 3c 45 [2] 30 4f [2] 27 44 [2] 3c 0a [2] 01 }

  condition:
    any of them
}