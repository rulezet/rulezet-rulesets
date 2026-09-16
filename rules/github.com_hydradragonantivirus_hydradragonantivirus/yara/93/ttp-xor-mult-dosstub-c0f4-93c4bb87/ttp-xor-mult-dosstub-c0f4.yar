rule TTP_XOR_MULT_DOSStub_c0f4 {
  strings:
    $key_c0f4 = { 94 9c [2] e0 84 [2] a7 86 [2] e0 97 [2] ae 9b [2] a2 91 [2] b5 9a [2] ae d4 [2] 93 }

  condition:
    any of them
}