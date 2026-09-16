rule TTP_XOR_MULT_DOSStub_2b94 {
  strings:
    $key_2b94 = { 7f fc [2] 0b e4 [2] 4c e6 [2] 0b f7 [2] 45 fb [2] 49 f1 [2] 5e fa [2] 45 b4 [2] 78 }

  condition:
    any of them
}