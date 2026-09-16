rule TTP_XOR_MULT_DOSStub_a701 {
  strings:
    $key_a701 = { f3 69 [2] 87 71 [2] c0 73 [2] 87 62 [2] c9 6e [2] c5 64 [2] d2 6f [2] c9 21 [2] f4 }

  condition:
    any of them
}