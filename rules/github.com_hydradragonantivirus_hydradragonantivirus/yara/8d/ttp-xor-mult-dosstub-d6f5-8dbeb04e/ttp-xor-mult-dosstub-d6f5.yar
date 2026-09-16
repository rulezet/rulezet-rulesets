rule TTP_XOR_MULT_DOSStub_d6f5 {
  strings:
    $key_d6f5 = { 82 9d [2] f6 85 [2] b1 87 [2] f6 96 [2] b8 9a [2] b4 90 [2] a3 9b [2] b8 d5 [2] 85 }

  condition:
    any of them
}