rule TTP_XOR_MULT_DOSStub_4752 {
  strings:
    $key_4752 = { 13 3a [2] 67 22 [2] 20 20 [2] 67 31 [2] 29 3d [2] 25 37 [2] 32 3c [2] 29 72 [2] 14 }

  condition:
    any of them
}