rule TTP_XOR_MULT_DOSStub_0248 {
  strings:
    $key_0248 = { 56 20 [2] 22 38 [2] 65 3a [2] 22 2b [2] 6c 27 [2] 60 2d [2] 77 26 [2] 6c 68 [2] 51 }

  condition:
    any of them
}