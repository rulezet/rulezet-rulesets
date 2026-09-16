rule TTP_XOR_MULT_DOSStub_5a59 {
  strings:
    $key_5a59 = { 0e 31 [2] 7a 29 [2] 3d 2b [2] 7a 3a [2] 34 36 [2] 38 3c [2] 2f 37 [2] 34 79 [2] 09 }

  condition:
    any of them
}