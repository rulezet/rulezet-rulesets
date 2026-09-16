rule TTP_XOR_MULT_DOSStub_7752 {
  strings:
    $key_7752 = { 23 3a [2] 57 22 [2] 10 20 [2] 57 31 [2] 19 3d [2] 15 37 [2] 02 3c [2] 19 72 [2] 24 }

  condition:
    any of them
}