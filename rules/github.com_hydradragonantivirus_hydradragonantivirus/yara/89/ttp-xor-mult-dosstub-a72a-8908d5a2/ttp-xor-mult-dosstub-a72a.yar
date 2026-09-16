rule TTP_XOR_MULT_DOSStub_a72a {
  strings:
    $key_a72a = { f3 42 [2] 87 5a [2] c0 58 [2] 87 49 [2] c9 45 [2] c5 4f [2] d2 44 [2] c9 0a [2] f4 }

  condition:
    any of them
}