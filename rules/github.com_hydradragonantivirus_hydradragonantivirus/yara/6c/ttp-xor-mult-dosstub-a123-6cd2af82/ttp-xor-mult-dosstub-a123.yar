rule TTP_XOR_MULT_DOSStub_a123 {
  strings:
    $key_a123 = { f5 4b [2] 81 53 [2] c6 51 [2] 81 40 [2] cf 4c [2] c3 46 [2] d4 4d [2] cf 03 [2] f2 }

  condition:
    any of them
}