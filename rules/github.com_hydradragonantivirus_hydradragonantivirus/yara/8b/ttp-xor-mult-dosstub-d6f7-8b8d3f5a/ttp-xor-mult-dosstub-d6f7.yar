rule TTP_XOR_MULT_DOSStub_d6f7 {
  strings:
    $key_d6f7 = { 82 9f [2] f6 87 [2] b1 85 [2] f6 94 [2] b8 98 [2] b4 92 [2] a3 99 [2] b8 d7 [2] 85 }

  condition:
    any of them
}