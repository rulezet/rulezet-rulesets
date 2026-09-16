rule TTP_XOR_MULT_DOSStub_8a87 {
  strings:
    $key_8a87 = { de ef [2] aa f7 [2] ed f5 [2] aa e4 [2] e4 e8 [2] e8 e2 [2] ff e9 [2] e4 a7 [2] d9 }

  condition:
    any of them
}