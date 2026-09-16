rule TTP_XOR_MULT_DOSStub_c719 {
  strings:
    $key_c719 = { 93 71 [2] e7 69 [2] a0 6b [2] e7 7a [2] a9 76 [2] a5 7c [2] b2 77 [2] a9 39 [2] 94 }

  condition:
    any of them
}