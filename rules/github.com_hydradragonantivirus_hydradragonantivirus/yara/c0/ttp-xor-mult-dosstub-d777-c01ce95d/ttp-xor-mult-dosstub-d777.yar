rule TTP_XOR_MULT_DOSStub_d777 {
  strings:
    $key_d777 = { 83 1f [2] f7 07 [2] b0 05 [2] f7 14 [2] b9 18 [2] b5 12 [2] a2 19 [2] b9 57 [2] 84 }

  condition:
    any of them
}