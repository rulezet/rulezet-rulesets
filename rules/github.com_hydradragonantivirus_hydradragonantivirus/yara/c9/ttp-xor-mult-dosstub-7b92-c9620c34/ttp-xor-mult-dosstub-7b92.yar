rule TTP_XOR_MULT_DOSStub_7b92 {
  strings:
    $key_7b92 = { 2f fa [2] 5b e2 [2] 1c e0 [2] 5b f1 [2] 15 fd [2] 19 f7 [2] 0e fc [2] 15 b2 [2] 28 }

  condition:
    any of them
}