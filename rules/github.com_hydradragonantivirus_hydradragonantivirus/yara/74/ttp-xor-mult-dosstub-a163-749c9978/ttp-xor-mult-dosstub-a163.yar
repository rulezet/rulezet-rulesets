rule TTP_XOR_MULT_DOSStub_a163 {
  strings:
    $key_a163 = { f5 0b [2] 81 13 [2] c6 11 [2] 81 00 [2] cf 0c [2] c3 06 [2] d4 0d [2] cf 43 [2] f2 }

  condition:
    any of them
}