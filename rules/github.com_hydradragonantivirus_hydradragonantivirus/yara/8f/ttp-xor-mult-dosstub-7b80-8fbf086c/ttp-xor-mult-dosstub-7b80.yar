rule TTP_XOR_MULT_DOSStub_7b80 {
  strings:
    $key_7b80 = { 2f e8 [2] 5b f0 [2] 1c f2 [2] 5b e3 [2] 15 ef [2] 19 e5 [2] 0e ee [2] 15 a0 [2] 28 }

  condition:
    any of them
}