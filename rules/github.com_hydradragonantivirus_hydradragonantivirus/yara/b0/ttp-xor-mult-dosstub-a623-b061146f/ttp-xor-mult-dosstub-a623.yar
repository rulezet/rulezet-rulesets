rule TTP_XOR_MULT_DOSStub_a623 {
  strings:
    $key_a623 = { f2 4b [2] 86 53 [2] c1 51 [2] 86 40 [2] c8 4c [2] c4 46 [2] d3 4d [2] c8 03 [2] f5 }

  condition:
    any of them
}