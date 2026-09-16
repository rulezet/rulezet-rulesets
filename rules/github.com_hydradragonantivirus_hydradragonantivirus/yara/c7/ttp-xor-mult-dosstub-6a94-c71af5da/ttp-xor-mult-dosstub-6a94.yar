rule TTP_XOR_MULT_DOSStub_6a94 {
  strings:
    $key_6a94 = { 3e fc [2] 4a e4 [2] 0d e6 [2] 4a f7 [2] 04 fb [2] 08 f1 [2] 1f fa [2] 04 b4 [2] 39 }

  condition:
    any of them
}