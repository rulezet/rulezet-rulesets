rule TTP_XOR_MULT_DOSStub_a703 {
  strings:
    $key_a703 = { f3 6b [2] 87 73 [2] c0 71 [2] 87 60 [2] c9 6c [2] c5 66 [2] d2 6d [2] c9 23 [2] f4 }

  condition:
    any of them
}