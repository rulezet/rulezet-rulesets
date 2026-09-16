rule TTP_XOR_MULT_DOSStub_4a12 {
  strings:
    $key_4a12 = { 1e 7a [2] 6a 62 [2] 2d 60 [2] 6a 71 [2] 24 7d [2] 28 77 [2] 3f 7c [2] 24 32 [2] 19 }

  condition:
    any of them
}