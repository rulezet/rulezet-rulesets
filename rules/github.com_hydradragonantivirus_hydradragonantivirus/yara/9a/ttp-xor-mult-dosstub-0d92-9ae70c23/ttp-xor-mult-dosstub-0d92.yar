rule TTP_XOR_MULT_DOSStub_0d92 {
  strings:
    $key_0d92 = { 59 fa [2] 2d e2 [2] 6a e0 [2] 2d f1 [2] 63 fd [2] 6f f7 [2] 78 fc [2] 63 b2 [2] 5e }

  condition:
    any of them
}