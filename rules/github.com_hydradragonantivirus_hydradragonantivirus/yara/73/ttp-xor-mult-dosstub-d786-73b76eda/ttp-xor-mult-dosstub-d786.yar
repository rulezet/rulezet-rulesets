rule TTP_XOR_MULT_DOSStub_d786 {
  strings:
    $key_d786 = { 83 ee [2] f7 f6 [2] b0 f4 [2] f7 e5 [2] b9 e9 [2] b5 e3 [2] a2 e8 [2] b9 a6 [2] 84 }

  condition:
    any of them
}