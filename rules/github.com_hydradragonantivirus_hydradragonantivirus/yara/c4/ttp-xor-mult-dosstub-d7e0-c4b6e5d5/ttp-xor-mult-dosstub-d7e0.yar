rule TTP_XOR_MULT_DOSStub_d7e0 {
  strings:
    $key_d7e0 = { 83 88 [2] f7 90 [2] b0 92 [2] f7 83 [2] b9 8f [2] b5 85 [2] a2 8e [2] b9 c0 [2] 84 }

  condition:
    any of them
}