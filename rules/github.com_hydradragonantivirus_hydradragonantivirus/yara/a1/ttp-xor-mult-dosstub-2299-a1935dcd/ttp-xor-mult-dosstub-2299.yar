rule TTP_XOR_MULT_DOSStub_2299 {
  strings:
    $key_2299 = { 76 f1 [2] 02 e9 [2] 45 eb [2] 02 fa [2] 4c f6 [2] 40 fc [2] 57 f7 [2] 4c b9 [2] 71 }

  condition:
    any of them
}