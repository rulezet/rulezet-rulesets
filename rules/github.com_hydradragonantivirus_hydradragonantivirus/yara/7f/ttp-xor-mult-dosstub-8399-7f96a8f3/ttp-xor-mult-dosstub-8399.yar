rule TTP_XOR_MULT_DOSStub_8399 {
  strings:
    $key_8399 = { d7 f1 [2] a3 e9 [2] e4 eb [2] a3 fa [2] ed f6 [2] e1 fc [2] f6 f7 [2] ed b9 [2] d0 }

  condition:
    any of them
}