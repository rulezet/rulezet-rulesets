rule TTP_XOR_MULT_DOSStub_a15a {
  strings:
    $key_a15a = { f5 32 [2] 81 2a [2] c6 28 [2] 81 39 [2] cf 35 [2] c3 3f [2] d4 34 [2] cf 7a [2] f2 }

  condition:
    any of them
}