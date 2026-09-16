rule TTP_XOR_MULT_DOSStub_ec95 {
  strings:
    $key_ec95 = { b8 fd [2] cc e5 [2] 8b e7 [2] cc f6 [2] 82 fa [2] 8e f0 [2] 99 fb [2] 82 b5 [2] bf }

  condition:
    any of them
}