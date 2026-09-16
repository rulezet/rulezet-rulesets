rule TTP_XOR_MULT_DOSStub_3b80 {
  strings:
    $key_3b80 = { 6f e8 [2] 1b f0 [2] 5c f2 [2] 1b e3 [2] 55 ef [2] 59 e5 [2] 4e ee [2] 55 a0 [2] 68 }

  condition:
    any of them
}