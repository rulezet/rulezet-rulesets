rule TTP_XOR_MULT_DOSStub_c889 {
  strings:
    $key_c889 = { 9c e1 [2] e8 f9 [2] af fb [2] e8 ea [2] a6 e6 [2] aa ec [2] bd e7 [2] a6 a9 [2] 9b }

  condition:
    any of them
}