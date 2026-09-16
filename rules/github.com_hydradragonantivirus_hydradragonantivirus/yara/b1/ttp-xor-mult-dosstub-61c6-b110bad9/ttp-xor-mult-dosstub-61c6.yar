rule TTP_XOR_MULT_DOSStub_61c6 {
  strings:
    $key_61c6 = { 35 ae [2] 41 b6 [2] 06 b4 [2] 41 a5 [2] 0f a9 [2] 03 a3 [2] 14 a8 [2] 0f e6 [2] 32 }

  condition:
    any of them
}