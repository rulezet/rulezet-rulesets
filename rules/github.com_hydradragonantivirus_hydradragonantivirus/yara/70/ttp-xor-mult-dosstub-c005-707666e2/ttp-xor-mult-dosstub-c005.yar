rule TTP_XOR_MULT_DOSStub_c005 {
  strings:
    $key_c005 = { 94 6d [2] e0 75 [2] a7 77 [2] e0 66 [2] ae 6a [2] a2 60 [2] b5 6b [2] ae 25 [2] 93 }

  condition:
    any of them
}