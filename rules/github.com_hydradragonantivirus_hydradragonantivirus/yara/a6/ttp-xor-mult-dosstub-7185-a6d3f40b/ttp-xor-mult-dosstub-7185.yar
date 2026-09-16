rule TTP_XOR_MULT_DOSStub_7185 {
  strings:
    $key_7185 = { 25 ed [2] 51 f5 [2] 16 f7 [2] 51 e6 [2] 1f ea [2] 13 e0 [2] 04 eb [2] 1f a5 [2] 22 }

  condition:
    any of them
}