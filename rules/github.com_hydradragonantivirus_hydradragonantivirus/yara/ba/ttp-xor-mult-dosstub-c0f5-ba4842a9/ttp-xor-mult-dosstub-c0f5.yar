rule TTP_XOR_MULT_DOSStub_c0f5 {
  strings:
    $key_c0f5 = { 94 9d [2] e0 85 [2] a7 87 [2] e0 96 [2] ae 9a [2] a2 90 [2] b5 9b [2] ae d5 [2] 93 }

  condition:
    any of them
}