rule TTP_XOR_MULT_DOSStub_c014 {
  strings:
    $key_c014 = { 94 7c [2] e0 64 [2] a7 66 [2] e0 77 [2] ae 7b [2] a2 71 [2] b5 7a [2] ae 34 [2] 93 }

  condition:
    any of them
}