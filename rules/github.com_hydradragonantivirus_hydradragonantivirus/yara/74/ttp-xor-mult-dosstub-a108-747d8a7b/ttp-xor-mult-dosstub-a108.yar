rule TTP_XOR_MULT_DOSStub_a108 {
  strings:
    $key_a108 = { f5 60 [2] 81 78 [2] c6 7a [2] 81 6b [2] cf 67 [2] c3 6d [2] d4 66 [2] cf 28 [2] f2 }

  condition:
    any of them
}