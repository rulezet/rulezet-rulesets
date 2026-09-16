rule TTP_XOR_MULT_DOSStub_6399 {
  strings:
    $key_6399 = { 37 f1 [2] 43 e9 [2] 04 eb [2] 43 fa [2] 0d f6 [2] 01 fc [2] 16 f7 [2] 0d b9 [2] 30 }

  condition:
    any of them
}