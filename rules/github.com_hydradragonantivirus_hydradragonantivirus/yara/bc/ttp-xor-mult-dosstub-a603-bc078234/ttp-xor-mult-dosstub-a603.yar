rule TTP_XOR_MULT_DOSStub_a603 {
  strings:
    $key_a603 = { f2 6b [2] 86 73 [2] c1 71 [2] 86 60 [2] c8 6c [2] c4 66 [2] d3 6d [2] c8 23 [2] f5 }

  condition:
    any of them
}