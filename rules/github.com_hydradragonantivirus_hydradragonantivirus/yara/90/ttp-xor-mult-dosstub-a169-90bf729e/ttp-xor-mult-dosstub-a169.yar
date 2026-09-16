rule TTP_XOR_MULT_DOSStub_a169 {
  strings:
    $key_a169 = { f5 01 [2] 81 19 [2] c6 1b [2] 81 0a [2] cf 06 [2] c3 0c [2] d4 07 [2] cf 49 [2] f2 }

  condition:
    any of them
}