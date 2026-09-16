rule TTP_XOR_MULT_DOSStub_ed87 {
  strings:
    $key_ed87 = { b9 ef [2] cd f7 [2] 8a f5 [2] cd e4 [2] 83 e8 [2] 8f e2 [2] 98 e9 [2] 83 a7 [2] be }

  condition:
    any of them
}