rule TTP_XOR_MULT_DOSStub_d615 {
  strings:
    $key_d615 = { 82 7d [2] f6 65 [2] b1 67 [2] f6 76 [2] b8 7a [2] b4 70 [2] a3 7b [2] b8 35 [2] 85 }

  condition:
    any of them
}