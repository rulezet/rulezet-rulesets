rule TTP_XOR_MULT_DOSStub_c885 {
  strings:
    $key_c885 = { 9c ed [2] e8 f5 [2] af f7 [2] e8 e6 [2] a6 ea [2] aa e0 [2] bd eb [2] a6 a5 [2] 9b }

  condition:
    any of them
}