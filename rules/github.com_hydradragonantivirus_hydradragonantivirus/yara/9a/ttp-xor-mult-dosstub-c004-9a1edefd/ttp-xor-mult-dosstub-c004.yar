rule TTP_XOR_MULT_DOSStub_c004 {
  strings:
    $key_c004 = { 94 6c [2] e0 74 [2] a7 76 [2] e0 67 [2] ae 6b [2] a2 61 [2] b5 6a [2] ae 24 [2] 93 }

  condition:
    any of them
}