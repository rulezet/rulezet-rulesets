rule TTP_XOR_MULT_DOSStub_6199 {
  strings:
    $key_6199 = { 35 f1 [2] 41 e9 [2] 06 eb [2] 41 fa [2] 0f f6 [2] 03 fc [2] 14 f7 [2] 0f b9 [2] 32 }

  condition:
    any of them
}