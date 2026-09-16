rule TTP_XOR_MULT_DOSStub_a611 {
  strings:
    $key_a611 = { f2 79 [2] 86 61 [2] c1 63 [2] 86 72 [2] c8 7e [2] c4 74 [2] d3 7f [2] c8 31 [2] f5 }

  condition:
    any of them
}