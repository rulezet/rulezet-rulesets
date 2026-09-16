rule TTP_XOR_MULT_DOSStub_dd90 {
  strings:
    $key_dd90 = { 89 f8 [2] fd e0 [2] ba e2 [2] fd f3 [2] b3 ff [2] bf f5 [2] a8 fe [2] b3 b0 [2] 8e }

  condition:
    any of them
}