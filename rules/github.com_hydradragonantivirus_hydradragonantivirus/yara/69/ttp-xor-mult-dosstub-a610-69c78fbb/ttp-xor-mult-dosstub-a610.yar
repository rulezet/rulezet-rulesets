rule TTP_XOR_MULT_DOSStub_a610 {
  strings:
    $key_a610 = { f2 78 [2] 86 60 [2] c1 62 [2] 86 73 [2] c8 7f [2] c4 75 [2] d3 7e [2] c8 30 [2] f5 }

  condition:
    any of them
}