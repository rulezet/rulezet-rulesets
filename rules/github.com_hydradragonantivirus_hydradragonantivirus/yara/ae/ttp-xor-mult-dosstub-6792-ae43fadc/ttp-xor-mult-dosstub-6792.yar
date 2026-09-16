rule TTP_XOR_MULT_DOSStub_6792 {
  strings:
    $key_6792 = { 33 fa [2] 47 e2 [2] 00 e0 [2] 47 f1 [2] 09 fd [2] 05 f7 [2] 12 fc [2] 09 b2 [2] 34 }

  condition:
    any of them
}