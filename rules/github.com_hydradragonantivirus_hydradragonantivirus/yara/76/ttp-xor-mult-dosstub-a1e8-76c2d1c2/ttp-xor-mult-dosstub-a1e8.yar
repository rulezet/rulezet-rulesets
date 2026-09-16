rule TTP_XOR_MULT_DOSStub_a1e8 {
  strings:
    $key_a1e8 = { f5 80 [2] 81 98 [2] c6 9a [2] 81 8b [2] cf 87 [2] c3 8d [2] d4 86 [2] cf c8 [2] f2 }

  condition:
    any of them
}