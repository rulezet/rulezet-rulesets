rule TTP_XOR_MULT_DOSStub_d6e6 {
  strings:
    $key_d6e6 = { 82 8e [2] f6 96 [2] b1 94 [2] f6 85 [2] b8 89 [2] b4 83 [2] a3 88 [2] b8 c6 [2] 85 }

  condition:
    any of them
}