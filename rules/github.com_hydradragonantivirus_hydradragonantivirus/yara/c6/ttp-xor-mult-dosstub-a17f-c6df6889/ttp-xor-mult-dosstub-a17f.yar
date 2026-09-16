rule TTP_XOR_MULT_DOSStub_a17f {
  strings:
    $key_a17f = { f5 17 [2] 81 0f [2] c6 0d [2] 81 1c [2] cf 10 [2] c3 1a [2] d4 11 [2] cf 5f [2] f2 }

  condition:
    any of them
}