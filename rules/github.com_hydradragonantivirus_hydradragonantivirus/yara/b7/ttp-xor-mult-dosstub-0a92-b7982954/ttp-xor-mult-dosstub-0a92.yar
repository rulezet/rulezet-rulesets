rule TTP_XOR_MULT_DOSStub_0a92 {
  strings:
    $key_0a92 = { 5e fa [2] 2a e2 [2] 6d e0 [2] 2a f1 [2] 64 fd [2] 68 f7 [2] 7f fc [2] 64 b2 [2] 59 }

  condition:
    any of them
}