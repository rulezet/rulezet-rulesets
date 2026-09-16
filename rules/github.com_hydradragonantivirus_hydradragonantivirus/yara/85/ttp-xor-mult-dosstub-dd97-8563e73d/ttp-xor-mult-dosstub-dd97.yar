rule TTP_XOR_MULT_DOSStub_dd97 {
  strings:
    $key_dd97 = { 89 ff [2] fd e7 [2] ba e5 [2] fd f4 [2] b3 f8 [2] bf f2 [2] a8 f9 [2] b3 b7 [2] 8e }

  condition:
    any of them
}