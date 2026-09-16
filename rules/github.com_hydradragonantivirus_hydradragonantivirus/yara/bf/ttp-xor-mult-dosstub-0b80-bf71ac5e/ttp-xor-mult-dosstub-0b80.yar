rule TTP_XOR_MULT_DOSStub_0b80 {
  strings:
    $key_0b80 = { 5f e8 [2] 2b f0 [2] 6c f2 [2] 2b e3 [2] 65 ef [2] 69 e5 [2] 7e ee [2] 65 a0 [2] 58 }

  condition:
    any of them
}