rule TTP_XOR_MULT_DOSStub_d737 {
  strings:
    $key_d737 = { 83 5f [2] f7 47 [2] b0 45 [2] f7 54 [2] b9 58 [2] b5 52 [2] a2 59 [2] b9 17 [2] 84 }

  condition:
    any of them
}