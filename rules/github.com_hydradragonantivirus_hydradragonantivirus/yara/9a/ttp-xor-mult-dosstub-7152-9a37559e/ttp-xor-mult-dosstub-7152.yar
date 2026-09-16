rule TTP_XOR_MULT_DOSStub_7152 {
  strings:
    $key_7152 = { 25 3a [2] 51 22 [2] 16 20 [2] 51 31 [2] 1f 3d [2] 13 37 [2] 04 3c [2] 1f 72 [2] 22 }

  condition:
    any of them
}