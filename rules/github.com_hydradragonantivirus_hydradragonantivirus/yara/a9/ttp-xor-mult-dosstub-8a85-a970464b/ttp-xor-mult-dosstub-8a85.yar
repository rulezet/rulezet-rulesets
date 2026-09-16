rule TTP_XOR_MULT_DOSStub_8a85 {
  strings:
    $key_8a85 = { de ed [2] aa f5 [2] ed f7 [2] aa e6 [2] e4 ea [2] e8 e0 [2] ff eb [2] e4 a5 [2] d9 }

  condition:
    any of them
}