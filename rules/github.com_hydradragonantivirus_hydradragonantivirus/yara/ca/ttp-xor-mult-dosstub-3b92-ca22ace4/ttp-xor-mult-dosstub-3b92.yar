rule TTP_XOR_MULT_DOSStub_3b92 {
  strings:
    $key_3b92 = { 6f fa [2] 1b e2 [2] 5c e0 [2] 1b f1 [2] 55 fd [2] 59 f7 [2] 4e fc [2] 55 b2 [2] 68 }

  condition:
    any of them
}