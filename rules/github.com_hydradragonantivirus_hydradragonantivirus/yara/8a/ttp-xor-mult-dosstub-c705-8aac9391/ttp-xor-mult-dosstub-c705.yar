rule TTP_XOR_MULT_DOSStub_c705 {
  strings:
    $key_c705 = { 93 6d [2] e7 75 [2] a0 77 [2] e7 66 [2] a9 6a [2] a5 60 [2] b2 6b [2] a9 25 [2] 94 }

  condition:
    any of them
}