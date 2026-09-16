rule TTP_XOR_MULT_DOSStub_5ae2 {
  strings:
    $key_5ae2 = { 0e 8a [2] 7a 92 [2] 3d 90 [2] 7a 81 [2] 34 8d [2] 38 87 [2] 2f 8c [2] 34 c2 [2] 09 }

  condition:
    any of them
}