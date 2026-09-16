rule TTP_XOR_MULT_DOSStub_a651 {
  strings:
    $key_a651 = { f2 39 [2] 86 21 [2] c1 23 [2] 86 32 [2] c8 3e [2] c4 34 [2] d3 3f [2] c8 71 [2] f5 }

  condition:
    any of them
}