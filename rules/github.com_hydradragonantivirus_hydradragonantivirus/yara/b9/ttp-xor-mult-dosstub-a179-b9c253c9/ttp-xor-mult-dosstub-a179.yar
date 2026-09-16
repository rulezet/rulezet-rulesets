rule TTP_XOR_MULT_DOSStub_a179 {
  strings:
    $key_a179 = { f5 11 [2] 81 09 [2] c6 0b [2] 81 1a [2] cf 16 [2] c3 1c [2] d4 17 [2] cf 59 [2] f2 }

  condition:
    any of them
}