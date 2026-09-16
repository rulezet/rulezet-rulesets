rule TTP_XOR_MULT_DOSStub_c888 {
  strings:
    $key_c888 = { 9c e0 [2] e8 f8 [2] af fa [2] e8 eb [2] a6 e7 [2] aa ed [2] bd e6 [2] a6 a8 [2] 9b }

  condition:
    any of them
}