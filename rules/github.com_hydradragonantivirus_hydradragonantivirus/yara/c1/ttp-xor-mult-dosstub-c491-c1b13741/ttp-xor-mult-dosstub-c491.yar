rule TTP_XOR_MULT_DOSStub_c491 {
  strings:
    $key_c491 = { 90 f9 [2] e4 e1 [2] a3 e3 [2] e4 f2 [2] aa fe [2] a6 f4 [2] b1 ff [2] aa b1 [2] 97 }

  condition:
    any of them
}