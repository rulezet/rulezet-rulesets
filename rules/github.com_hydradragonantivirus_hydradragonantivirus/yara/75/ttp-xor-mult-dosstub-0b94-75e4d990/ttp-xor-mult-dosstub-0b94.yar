rule TTP_XOR_MULT_DOSStub_0b94 {
  strings:
    $key_0b94 = { 5f fc [2] 2b e4 [2] 6c e6 [2] 2b f7 [2] 65 fb [2] 69 f1 [2] 7e fa [2] 65 b4 [2] 58 }

  condition:
    any of them
}