rule TTP_XOR_MULT_DOSStub_ec92 {
  strings:
    $key_ec92 = { b8 fa [2] cc e2 [2] 8b e0 [2] cc f1 [2] 82 fd [2] 8e f7 [2] 99 fc [2] 82 b2 [2] bf }

  condition:
    any of them
}