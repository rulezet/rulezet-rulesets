rule TTP_XOR_MULT_DOSStub_6b94 {
  strings:
    $key_6b94 = { 3f fc [2] 4b e4 [2] 0c e6 [2] 4b f7 [2] 05 fb [2] 09 f1 [2] 1e fa [2] 05 b4 [2] 38 }

  condition:
    any of them
}