rule TTP_XOR_MULT_DOSStub_472a {
  strings:
    $key_472a = { 13 42 [2] 67 5a [2] 20 58 [2] 67 49 [2] 29 45 [2] 25 4f [2] 32 44 [2] 29 0a [2] 14 }

  condition:
    any of them
}