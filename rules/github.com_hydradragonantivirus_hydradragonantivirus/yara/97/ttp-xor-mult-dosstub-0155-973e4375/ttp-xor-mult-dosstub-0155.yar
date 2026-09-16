rule TTP_XOR_MULT_DOSStub_0155 {
  strings:
    $key_0155 = { 55 3d [2] 21 25 [2] 66 27 [2] 21 36 [2] 6f 3a [2] 63 30 [2] 74 3b [2] 6f 75 [2] 52 }

  condition:
    any of them
}