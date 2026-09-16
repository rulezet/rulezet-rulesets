rule TTP_XOR_MULT_DOSStub_d756 {
  strings:
    $key_d756 = { 83 3e [2] f7 26 [2] b0 24 [2] f7 35 [2] b9 39 [2] b5 33 [2] a2 38 [2] b9 76 [2] 84 }

  condition:
    any of them
}