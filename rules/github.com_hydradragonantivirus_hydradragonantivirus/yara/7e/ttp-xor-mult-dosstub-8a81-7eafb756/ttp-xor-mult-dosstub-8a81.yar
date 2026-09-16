rule TTP_XOR_MULT_DOSStub_8a81 {
  strings:
    $key_8a81 = { de e9 [2] aa f1 [2] ed f3 [2] aa e2 [2] e4 ee [2] e8 e4 [2] ff ef [2] e4 a1 [2] d9 }

  condition:
    any of them
}