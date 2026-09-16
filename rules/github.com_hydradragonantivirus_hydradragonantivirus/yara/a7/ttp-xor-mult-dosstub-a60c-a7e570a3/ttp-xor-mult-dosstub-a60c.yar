rule TTP_XOR_MULT_DOSStub_a60c {
  strings:
    $key_a60c = { f2 64 [2] 86 7c [2] c1 7e [2] 86 6f [2] c8 63 [2] c4 69 [2] d3 62 [2] c8 2c [2] f5 }

  condition:
    any of them
}