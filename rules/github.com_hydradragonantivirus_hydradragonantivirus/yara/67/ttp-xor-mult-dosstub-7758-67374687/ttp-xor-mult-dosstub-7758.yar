rule TTP_XOR_MULT_DOSStub_7758 {
  strings:
    $key_7758 = { 23 30 [2] 57 28 [2] 10 2a [2] 57 3b [2] 19 37 [2] 15 3d [2] 02 36 [2] 19 78 [2] 24 }

  condition:
    any of them
}