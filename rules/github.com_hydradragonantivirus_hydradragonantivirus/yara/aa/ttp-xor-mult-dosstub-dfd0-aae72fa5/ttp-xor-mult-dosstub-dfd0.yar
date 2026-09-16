rule TTP_XOR_MULT_DOSStub_dfd0 {
  strings:
    $key_dfd0 = { 8b b8 [2] ff a0 [2] b8 a2 [2] ff b3 [2] b1 bf [2] bd b5 [2] aa be [2] b1 f0 [2] 8c }

  condition:
    any of them
}