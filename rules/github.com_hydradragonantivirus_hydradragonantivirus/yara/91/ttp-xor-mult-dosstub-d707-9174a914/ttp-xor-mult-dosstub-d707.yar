rule TTP_XOR_MULT_DOSStub_d707 {
  strings:
    $key_d707 = { 83 6f [2] f7 77 [2] b0 75 [2] f7 64 [2] b9 68 [2] b5 62 [2] a2 69 [2] b9 27 [2] 84 }

  condition:
    any of them
}