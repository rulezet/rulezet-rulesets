rule TTP_XOR_MULT_DOSStub_c0ca {
  strings:
    $key_c0ca = { 94 a2 [2] e0 ba [2] a7 b8 [2] e0 a9 [2] ae a5 [2] a2 af [2] b5 a4 [2] ae ea [2] 93 }

  condition:
    any of them
}