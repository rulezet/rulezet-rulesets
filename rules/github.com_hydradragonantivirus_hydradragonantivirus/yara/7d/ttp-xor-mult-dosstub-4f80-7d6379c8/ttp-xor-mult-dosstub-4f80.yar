rule TTP_XOR_MULT_DOSStub_4f80 {
  strings:
    $key_4f80 = { 1b e8 [2] 6f f0 [2] 28 f2 [2] 6f e3 [2] 21 ef [2] 2d e5 [2] 3a ee [2] 21 a0 [2] 1c }

  condition:
    any of them
}