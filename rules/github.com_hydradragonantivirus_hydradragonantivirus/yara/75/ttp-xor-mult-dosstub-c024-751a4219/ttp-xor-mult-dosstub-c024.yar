rule TTP_XOR_MULT_DOSStub_c024 {
  strings:
    $key_c024 = { 94 4c [2] e0 54 [2] a7 56 [2] e0 47 [2] ae 4b [2] a2 41 [2] b5 4a [2] ae 04 [2] 93 }

  condition:
    any of them
}