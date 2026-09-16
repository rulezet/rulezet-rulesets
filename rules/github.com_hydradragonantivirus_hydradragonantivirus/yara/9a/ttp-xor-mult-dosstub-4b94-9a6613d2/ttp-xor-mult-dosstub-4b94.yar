rule TTP_XOR_MULT_DOSStub_4b94 {
  strings:
    $key_4b94 = { 1f fc [2] 6b e4 [2] 2c e6 [2] 6b f7 [2] 25 fb [2] 29 f1 [2] 3e fa [2] 25 b4 [2] 18 }

  condition:
    any of them
}