rule TTP_XOR_MULT_DOSStub_c883 {
  strings:
    $key_c883 = { 9c eb [2] e8 f3 [2] af f1 [2] e8 e0 [2] a6 ec [2] aa e6 [2] bd ed [2] a6 a3 [2] 9b }

  condition:
    any of them
}