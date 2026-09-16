rule TTP_XOR_MULT_DOSStub_2f81 {
  strings:
    $key_2f81 = { 7b e9 [2] 0f f1 [2] 48 f3 [2] 0f e2 [2] 41 ee [2] 4d e4 [2] 5a ef [2] 41 a1 [2] 7c }

  condition:
    any of them
}