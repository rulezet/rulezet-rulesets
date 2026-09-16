rule TTP_XOR_MULT_DOSStub_d6f0 {
  strings:
    $key_d6f0 = { 82 98 [2] f6 80 [2] b1 82 [2] f6 93 [2] b8 9f [2] b4 95 [2] a3 9e [2] b8 d0 [2] 85 }

  condition:
    any of them
}