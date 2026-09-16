rule TTP_XOR_MULT_DOSStub_c068 {
  strings:
    $key_c068 = { 94 00 [2] e0 18 [2] a7 1a [2] e0 0b [2] ae 07 [2] a2 0d [2] b5 06 [2] ae 48 [2] 93 }

  condition:
    any of them
}