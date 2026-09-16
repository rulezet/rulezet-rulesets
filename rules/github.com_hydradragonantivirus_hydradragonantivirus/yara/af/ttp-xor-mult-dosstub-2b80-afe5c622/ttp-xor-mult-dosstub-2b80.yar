rule TTP_XOR_MULT_DOSStub_2b80 {
  strings:
    $key_2b80 = { 7f e8 [2] 0b f0 [2] 4c f2 [2] 0b e3 [2] 45 ef [2] 49 e5 [2] 5e ee [2] 45 a0 [2] 78 }

  condition:
    any of them
}