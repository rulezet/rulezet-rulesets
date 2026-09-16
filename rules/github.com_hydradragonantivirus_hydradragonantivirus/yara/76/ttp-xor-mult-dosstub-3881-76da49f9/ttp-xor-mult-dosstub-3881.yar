rule TTP_XOR_MULT_DOSStub_3881 {
  strings:
    $key_3881 = { 6c e9 [2] 18 f1 [2] 5f f3 [2] 18 e2 [2] 56 ee [2] 5a e4 [2] 4d ef [2] 56 a1 [2] 6b }

  condition:
    any of them
}