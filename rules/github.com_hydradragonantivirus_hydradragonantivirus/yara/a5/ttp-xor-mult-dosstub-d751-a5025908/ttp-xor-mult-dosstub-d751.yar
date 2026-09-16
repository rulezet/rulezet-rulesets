rule TTP_XOR_MULT_DOSStub_d751 {
  strings:
    $key_d751 = { 83 39 [2] f7 21 [2] b0 23 [2] f7 32 [2] b9 3e [2] b5 34 [2] a2 3f [2] b9 71 [2] 84 }

  condition:
    any of them
}