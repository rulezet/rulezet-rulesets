rule TTP_XOR_MULT_DOSStub_6194 {
  strings:
    $key_6194 = { 35 fc [2] 41 e4 [2] 06 e6 [2] 41 f7 [2] 0f fb [2] 03 f1 [2] 14 fa [2] 0f b4 [2] 32 }

  condition:
    any of them
}