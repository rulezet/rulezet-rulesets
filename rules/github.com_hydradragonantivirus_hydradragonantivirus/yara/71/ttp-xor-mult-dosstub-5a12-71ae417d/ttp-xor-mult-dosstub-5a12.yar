rule TTP_XOR_MULT_DOSStub_5a12 {
  strings:
    $key_5a12 = { 0e 7a [2] 7a 62 [2] 3d 60 [2] 7a 71 [2] 34 7d [2] 38 77 [2] 2f 7c [2] 34 32 [2] 09 }

  condition:
    any of them
}