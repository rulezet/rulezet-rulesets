rule TTP_XOR_MULT_DOSStub_d757 {
  strings:
    $key_d757 = { 83 3f [2] f7 27 [2] b0 25 [2] f7 34 [2] b9 38 [2] b5 32 [2] a2 39 [2] b9 77 [2] 84 }

  condition:
    any of them
}