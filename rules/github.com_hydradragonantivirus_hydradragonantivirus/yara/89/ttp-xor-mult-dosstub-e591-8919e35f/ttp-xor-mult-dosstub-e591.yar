rule TTP_XOR_MULT_DOSStub_e591 {
  strings:
    $key_e591 = { b1 f9 [2] c5 e1 [2] 82 e3 [2] c5 f2 [2] 8b fe [2] 87 f4 [2] 90 ff [2] 8b b1 [2] b6 }

  condition:
    any of them
}