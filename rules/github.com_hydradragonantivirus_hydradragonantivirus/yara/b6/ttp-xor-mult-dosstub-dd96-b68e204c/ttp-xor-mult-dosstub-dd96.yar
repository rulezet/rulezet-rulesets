rule TTP_XOR_MULT_DOSStub_dd96 {
  strings:
    $key_dd96 = { 89 fe [2] fd e6 [2] ba e4 [2] fd f5 [2] b3 f9 [2] bf f3 [2] a8 f8 [2] b3 b6 [2] 8e }

  condition:
    any of them
}