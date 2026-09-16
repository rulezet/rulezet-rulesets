rule TTP_XOR_MULT_DOSStub_4a02 {
  strings:
    $key_4a02 = { 1e 6a [2] 6a 72 [2] 2d 70 [2] 6a 61 [2] 24 6d [2] 28 67 [2] 3f 6c [2] 24 22 [2] 19 }

  condition:
    any of them
}