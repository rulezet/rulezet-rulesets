rule TTP_XOR_MULT_DOSStub_2499 {
  strings:
    $key_2499 = { 70 f1 [2] 04 e9 [2] 43 eb [2] 04 fa [2] 4a f6 [2] 46 fc [2] 51 f7 [2] 4a b9 [2] 77 }

  condition:
    any of them
}