rule TTP_XOR_MULT_DOSStub_0d99 {
  strings:
    $key_0d99 = { 59 f1 [2] 2d e9 [2] 6a eb [2] 2d fa [2] 63 f6 [2] 6f fc [2] 78 f7 [2] 63 b9 [2] 5e }

  condition:
    any of them
}