rule TTP_XOR_MULT_DOSStub_6186 {
  strings:
    $key_6186 = { 35 ee [2] 41 f6 [2] 06 f4 [2] 41 e5 [2] 0f e9 [2] 03 e3 [2] 14 e8 [2] 0f a6 [2] 32 }

  condition:
    any of them
}