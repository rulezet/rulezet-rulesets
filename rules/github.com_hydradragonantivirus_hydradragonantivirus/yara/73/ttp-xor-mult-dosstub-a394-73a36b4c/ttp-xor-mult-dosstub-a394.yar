rule TTP_XOR_MULT_DOSStub_a394 {
  strings:
    $key_a394 = { f7 fc [2] 83 e4 [2] c4 e6 [2] 83 f7 [2] cd fb [2] c1 f1 [2] d6 fa [2] cd b4 [2] f0 }

  condition:
    any of them
}