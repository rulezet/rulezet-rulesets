rule TTP_XOR_MULT_DOSStub_5b80 {
  strings:
    $key_5b80 = { 0f e8 [2] 7b f0 [2] 3c f2 [2] 7b e3 [2] 35 ef [2] 39 e5 [2] 2e ee [2] 35 a0 [2] 08 }

  condition:
    any of them
}