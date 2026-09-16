rule TTP_XOR_MULT_DOSStub_d697 {
  strings:
    $key_d697 = { 82 ff [2] f6 e7 [2] b1 e5 [2] f6 f4 [2] b8 f8 [2] b4 f2 [2] a3 f9 [2] b8 b7 [2] 85 }

  condition:
    any of them
}