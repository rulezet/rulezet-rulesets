rule TTP_XOR_MULT_DOSStub_d701 {
  strings:
    $key_d701 = { 83 69 [2] f7 71 [2] b0 73 [2] f7 62 [2] b9 6e [2] b5 64 [2] a2 6f [2] b9 21 [2] 84 }

  condition:
    any of them
}