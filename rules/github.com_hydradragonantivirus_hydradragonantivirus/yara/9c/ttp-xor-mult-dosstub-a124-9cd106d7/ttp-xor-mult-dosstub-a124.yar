rule TTP_XOR_MULT_DOSStub_a124 {
  strings:
    $key_a124 = { f5 4c [2] 81 54 [2] c6 56 [2] 81 47 [2] cf 4b [2] c3 41 [2] d4 4a [2] cf 04 [2] f2 }

  condition:
    any of them
}