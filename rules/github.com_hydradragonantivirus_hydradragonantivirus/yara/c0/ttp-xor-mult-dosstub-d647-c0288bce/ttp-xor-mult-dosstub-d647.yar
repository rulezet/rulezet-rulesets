rule TTP_XOR_MULT_DOSStub_d647 {
  strings:
    $key_d647 = { 82 2f [2] f6 37 [2] b1 35 [2] f6 24 [2] b8 28 [2] b4 22 [2] a3 29 [2] b8 67 [2] 85 }

  condition:
    any of them
}