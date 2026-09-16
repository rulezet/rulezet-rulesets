rule TTP_XOR_MULT_DOSStub_3b81 {
  strings:
    $key_3b81 = { 6f e9 [2] 1b f1 [2] 5c f3 [2] 1b e2 [2] 55 ee [2] 59 e4 [2] 4e ef [2] 55 a1 [2] 68 }

  condition:
    any of them
}