rule TTP_XOR_MULT_DOSStub_a65c {
  strings:
    $key_a65c = { f2 34 [2] 86 2c [2] c1 2e [2] 86 3f [2] c8 33 [2] c4 39 [2] d3 32 [2] c8 7c [2] f5 }

  condition:
    any of them
}