rule TTP_XOR_MULT_DOSStub_a178 {
  strings:
    $key_a178 = { f5 10 [2] 81 08 [2] c6 0a [2] 81 1b [2] cf 17 [2] c3 1d [2] d4 16 [2] cf 58 [2] f2 }

  condition:
    any of them
}