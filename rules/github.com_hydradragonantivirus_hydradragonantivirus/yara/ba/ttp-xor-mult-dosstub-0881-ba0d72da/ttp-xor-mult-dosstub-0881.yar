rule TTP_XOR_MULT_DOSStub_0881 {
  strings:
    $key_0881 = { 5c e9 [2] 28 f1 [2] 6f f3 [2] 28 e2 [2] 66 ee [2] 6a e4 [2] 7d ef [2] 66 a1 [2] 5b }

  condition:
    any of them
}