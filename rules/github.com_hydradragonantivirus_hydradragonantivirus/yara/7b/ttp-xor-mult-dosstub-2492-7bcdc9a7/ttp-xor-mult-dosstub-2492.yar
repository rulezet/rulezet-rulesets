rule TTP_XOR_MULT_DOSStub_2492 {
  strings:
    $key_2492 = { 70 fa [2] 04 e2 [2] 43 e0 [2] 04 f1 [2] 4a fd [2] 46 f7 [2] 51 fc [2] 4a b2 [2] 77 }

  condition:
    any of them
}