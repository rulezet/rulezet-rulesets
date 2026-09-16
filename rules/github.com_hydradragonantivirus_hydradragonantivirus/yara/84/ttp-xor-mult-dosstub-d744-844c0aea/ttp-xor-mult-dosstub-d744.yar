rule TTP_XOR_MULT_DOSStub_d744 {
  strings:
    $key_d744 = { 83 2c [2] f7 34 [2] b0 36 [2] f7 27 [2] b9 2b [2] b5 21 [2] a2 2a [2] b9 64 [2] 84 }

  condition:
    any of them
}