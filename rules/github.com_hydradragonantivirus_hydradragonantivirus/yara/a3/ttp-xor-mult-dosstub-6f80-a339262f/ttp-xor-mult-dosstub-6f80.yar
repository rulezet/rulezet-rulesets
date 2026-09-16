rule TTP_XOR_MULT_DOSStub_6f80 {
  strings:
    $key_6f80 = { 3b e8 [2] 4f f0 [2] 08 f2 [2] 4f e3 [2] 01 ef [2] 0d e5 [2] 1a ee [2] 01 a0 [2] 3c }

  condition:
    any of them
}