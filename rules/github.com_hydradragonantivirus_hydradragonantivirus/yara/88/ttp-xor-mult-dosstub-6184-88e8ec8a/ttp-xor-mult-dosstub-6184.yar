rule TTP_XOR_MULT_DOSStub_6184 {
  strings:
    $key_6184 = { 35 ec [2] 41 f4 [2] 06 f6 [2] 41 e7 [2] 0f eb [2] 03 e1 [2] 14 ea [2] 0f a4 [2] 32 }

  condition:
    any of them
}