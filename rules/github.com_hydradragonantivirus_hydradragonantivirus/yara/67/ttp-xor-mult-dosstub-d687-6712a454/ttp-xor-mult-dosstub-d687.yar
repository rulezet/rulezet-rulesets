rule TTP_XOR_MULT_DOSStub_d687 {
  strings:
    $key_d687 = { 82 ef [2] f6 f7 [2] b1 f5 [2] f6 e4 [2] b8 e8 [2] b4 e2 [2] a3 e9 [2] b8 a7 [2] 85 }

  condition:
    any of them
}