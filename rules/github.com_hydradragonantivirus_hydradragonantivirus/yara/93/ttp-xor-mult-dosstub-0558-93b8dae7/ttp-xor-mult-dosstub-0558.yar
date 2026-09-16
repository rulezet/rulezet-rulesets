rule TTP_XOR_MULT_DOSStub_0558 {
  strings:
    $key_0558 = { 51 30 [2] 25 28 [2] 62 2a [2] 25 3b [2] 6b 37 [2] 67 3d [2] 70 36 [2] 6b 78 [2] 56 }

  condition:
    any of them
}