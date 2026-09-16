rule TTP_XOR_MULT_DOSStub_d656 {
  strings:
    $key_d656 = { 82 3e [2] f6 26 [2] b1 24 [2] f6 35 [2] b8 39 [2] b4 33 [2] a3 38 [2] b8 76 [2] 85 }

  condition:
    any of them
}