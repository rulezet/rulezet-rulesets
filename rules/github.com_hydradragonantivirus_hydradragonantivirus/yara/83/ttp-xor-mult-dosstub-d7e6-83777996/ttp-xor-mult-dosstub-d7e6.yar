rule TTP_XOR_MULT_DOSStub_d7e6 {
  strings:
    $key_d7e6 = { 83 8e [2] f7 96 [2] b0 94 [2] f7 85 [2] b9 89 [2] b5 83 [2] a2 88 [2] b9 c6 [2] 84 }

  condition:
    any of them
}