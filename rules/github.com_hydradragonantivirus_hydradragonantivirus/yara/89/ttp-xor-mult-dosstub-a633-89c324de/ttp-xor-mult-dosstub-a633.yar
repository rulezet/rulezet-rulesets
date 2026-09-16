rule TTP_XOR_MULT_DOSStub_a633 {
  strings:
    $key_a633 = { f2 5b [2] 86 43 [2] c1 41 [2] 86 50 [2] c8 5c [2] c4 56 [2] d3 5d [2] c8 13 [2] f5 }

  condition:
    any of them
}