rule TTP_XOR_MULT_DOSStub_6881 {
  strings:
    $key_6881 = { 3c e9 [2] 48 f1 [2] 0f f3 [2] 48 e2 [2] 06 ee [2] 0a e4 [2] 1d ef [2] 06 a1 [2] 3b }

  condition:
    any of them
}