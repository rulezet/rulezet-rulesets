rule TTP_XOR_MULT_DOSStub_c085 {
  strings:
    $key_c085 = { 94 ed [2] e0 f5 [2] a7 f7 [2] e0 e6 [2] ae ea [2] a2 e0 [2] b5 eb [2] ae a5 [2] 93 }

  condition:
    any of them
}