rule TTP_XOR_MULT_DOSStub_8a99 {
  strings:
    $key_8a99 = { de f1 [2] aa e9 [2] ed eb [2] aa fa [2] e4 f6 [2] e8 fc [2] ff f7 [2] e4 b9 [2] d9 }

  condition:
    any of them
}