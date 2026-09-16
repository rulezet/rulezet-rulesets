rule TTP_XOR_MULT_DOSStub_fb92 {
  strings:
    $key_fb92 = { af fa [2] db e2 [2] 9c e0 [2] db f1 [2] 95 fd [2] 99 f7 [2] 8e fc [2] 95 b2 [2] a8 }

  condition:
    any of them
}