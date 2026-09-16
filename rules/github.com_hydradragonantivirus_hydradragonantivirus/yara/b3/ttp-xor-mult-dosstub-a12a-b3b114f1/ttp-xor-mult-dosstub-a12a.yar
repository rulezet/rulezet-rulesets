rule TTP_XOR_MULT_DOSStub_a12a {
  strings:
    $key_a12a = { f5 42 [2] 81 5a [2] c6 58 [2] 81 49 [2] cf 45 [2] c3 4f [2] d4 44 [2] cf 0a [2] f2 }

  condition:
    any of them
}