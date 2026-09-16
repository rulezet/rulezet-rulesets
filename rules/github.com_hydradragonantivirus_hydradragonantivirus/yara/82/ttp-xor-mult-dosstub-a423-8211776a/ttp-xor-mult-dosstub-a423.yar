rule TTP_XOR_MULT_DOSStub_a423 {
  strings:
    $key_a423 = { f0 4b [2] 84 53 [2] c3 51 [2] 84 40 [2] ca 4c [2] c6 46 [2] d1 4d [2] ca 03 [2] f7 }

  condition:
    any of them
}