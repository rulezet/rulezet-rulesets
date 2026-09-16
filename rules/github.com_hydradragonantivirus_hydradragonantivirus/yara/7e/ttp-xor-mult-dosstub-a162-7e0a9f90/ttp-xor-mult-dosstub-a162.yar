rule TTP_XOR_MULT_DOSStub_a162 {
  strings:
    $key_a162 = { f5 0a [2] 81 12 [2] c6 10 [2] 81 01 [2] cf 0d [2] c3 07 [2] d4 0c [2] cf 42 [2] f2 }

  condition:
    any of them
}