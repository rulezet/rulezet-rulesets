rule TTP_XOR_MULT_DOSStub_a129 {
  strings:
    $key_a129 = { f5 41 [2] 81 59 [2] c6 5b [2] 81 4a [2] cf 46 [2] c3 4c [2] d4 47 [2] cf 09 [2] f2 }

  condition:
    any of them
}