rule TTP_XOR_MULT_DOSStub_a678 {
  strings:
    $key_a678 = { f2 10 [2] 86 08 [2] c1 0a [2] 86 1b [2] c8 17 [2] c4 1d [2] d3 16 [2] c8 58 [2] f5 }

  condition:
    any of them
}