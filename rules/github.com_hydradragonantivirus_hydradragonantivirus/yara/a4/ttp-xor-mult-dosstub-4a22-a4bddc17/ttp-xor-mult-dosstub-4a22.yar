rule TTP_XOR_MULT_DOSStub_4a22 {
  strings:
    $key_4a22 = { 1e 4a [2] 6a 52 [2] 2d 50 [2] 6a 41 [2] 24 4d [2] 28 47 [2] 3f 4c [2] 24 02 [2] 19 }

  condition:
    any of them
}