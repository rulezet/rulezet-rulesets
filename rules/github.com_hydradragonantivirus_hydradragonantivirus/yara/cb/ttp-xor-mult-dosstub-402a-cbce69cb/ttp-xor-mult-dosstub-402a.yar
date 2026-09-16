rule TTP_XOR_MULT_DOSStub_402a {
  strings:
    $key_402a = { 14 42 [2] 60 5a [2] 27 58 [2] 60 49 [2] 2e 45 [2] 22 4f [2] 35 44 [2] 2e 0a [2] 13 }

  condition:
    any of them
}