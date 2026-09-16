rule TTP_XOR_MULT_DOSStub_d790 {
  strings:
    $key_d790 = { 83 f8 [2] f7 e0 [2] b0 e2 [2] f7 f3 [2] b9 ff [2] b5 f5 [2] a2 fe [2] b9 b0 [2] 84 }

  condition:
    any of them
}