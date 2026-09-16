rule TTP_XOR_MULT_DOSStub_d720 {
  strings:
    $key_d720 = { 83 48 [2] f7 50 [2] b0 52 [2] f7 43 [2] b9 4f [2] b5 45 [2] a2 4e [2] b9 00 [2] 84 }

  condition:
    any of them
}