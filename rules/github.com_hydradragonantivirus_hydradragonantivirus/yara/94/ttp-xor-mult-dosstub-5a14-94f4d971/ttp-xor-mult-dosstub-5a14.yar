rule TTP_XOR_MULT_DOSStub_5a14 {
  strings:
    $key_5a14 = { 0e 7c [2] 7a 64 [2] 3d 66 [2] 7a 77 [2] 34 7b [2] 38 71 [2] 2f 7a [2] 34 34 [2] 09 }

  condition:
    any of them
}