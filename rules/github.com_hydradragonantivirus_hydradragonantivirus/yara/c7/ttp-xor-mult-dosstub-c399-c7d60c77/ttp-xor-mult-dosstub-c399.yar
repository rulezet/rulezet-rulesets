rule TTP_XOR_MULT_DOSStub_c399 {
  strings:
    $key_c399 = { 97 f1 [2] e3 e9 [2] a4 eb [2] e3 fa [2] ad f6 [2] a1 fc [2] b6 f7 [2] ad b9 [2] 90 }

  condition:
    any of them
}