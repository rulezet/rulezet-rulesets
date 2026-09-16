rule TTP_XOR_MULT_DOSStub_6185 {
  strings:
    $key_6185 = { 35 ed [2] 41 f5 [2] 06 f7 [2] 41 e6 [2] 0f ea [2] 03 e0 [2] 14 eb [2] 0f a5 [2] 32 }

  condition:
    any of them
}