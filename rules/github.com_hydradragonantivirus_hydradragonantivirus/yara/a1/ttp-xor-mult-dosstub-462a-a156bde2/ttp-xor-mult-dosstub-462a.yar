rule TTP_XOR_MULT_DOSStub_462a {
  strings:
    $key_462a = { 12 42 [2] 66 5a [2] 21 58 [2] 66 49 [2] 28 45 [2] 24 4f [2] 33 44 [2] 28 0a [2] 15 }

  condition:
    any of them
}