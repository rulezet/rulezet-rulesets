rule TTP_XOR_MULT_DOSStub_0f81 {
  strings:
    $key_0f81 = { 5b e9 [2] 2f f1 [2] 68 f3 [2] 2f e2 [2] 61 ee [2] 6d e4 [2] 7a ef [2] 61 a1 [2] 5c }

  condition:
    any of them
}