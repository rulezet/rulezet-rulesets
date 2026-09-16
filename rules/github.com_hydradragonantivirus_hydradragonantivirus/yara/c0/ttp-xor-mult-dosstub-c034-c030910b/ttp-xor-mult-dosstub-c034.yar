rule TTP_XOR_MULT_DOSStub_c034 {
  strings:
    $key_c034 = { 94 5c [2] e0 44 [2] a7 46 [2] e0 57 [2] ae 5b [2] a2 51 [2] b5 5a [2] ae 14 [2] 93 }

  condition:
    any of them
}