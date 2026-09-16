rule TTP_XOR_MULT_DOSStub_742a {
  strings:
    $key_742a = { 20 42 [2] 54 5a [2] 13 58 [2] 54 49 [2] 1a 45 [2] 16 4f [2] 01 44 [2] 1a 0a [2] 27 }

  condition:
    any of them
}