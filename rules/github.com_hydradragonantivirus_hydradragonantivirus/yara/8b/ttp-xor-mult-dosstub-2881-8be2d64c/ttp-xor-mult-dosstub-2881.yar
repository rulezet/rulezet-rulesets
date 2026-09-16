rule TTP_XOR_MULT_DOSStub_2881 {
  strings:
    $key_2881 = { 7c e9 [2] 08 f1 [2] 4f f3 [2] 08 e2 [2] 46 ee [2] 4a e4 [2] 5d ef [2] 46 a1 [2] 7b }

  condition:
    any of them
}