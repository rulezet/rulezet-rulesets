rule TTP_XOR_MULT_DOSStub_a128 {
  strings:
    $key_a128 = { f5 40 [2] 81 58 [2] c6 5a [2] 81 4b [2] cf 47 [2] c3 4d [2] d4 46 [2] cf 08 [2] f2 }

  condition:
    any of them
}