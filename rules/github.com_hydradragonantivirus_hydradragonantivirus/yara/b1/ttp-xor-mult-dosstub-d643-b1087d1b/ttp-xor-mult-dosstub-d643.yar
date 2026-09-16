rule TTP_XOR_MULT_DOSStub_d643 {
  strings:
    $key_d643 = { 82 2b [2] f6 33 [2] b1 31 [2] f6 20 [2] b8 2c [2] b4 26 [2] a3 2d [2] b8 63 [2] 85 }

  condition:
    any of them
}