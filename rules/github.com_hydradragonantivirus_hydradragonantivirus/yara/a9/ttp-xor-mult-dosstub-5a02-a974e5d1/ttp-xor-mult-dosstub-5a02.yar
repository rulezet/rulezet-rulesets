rule TTP_XOR_MULT_DOSStub_5a02 {
  strings:
    $key_5a02 = { 0e 6a [2] 7a 72 [2] 3d 70 [2] 7a 61 [2] 34 6d [2] 38 67 [2] 2f 6c [2] 34 22 [2] 09 }

  condition:
    any of them
}