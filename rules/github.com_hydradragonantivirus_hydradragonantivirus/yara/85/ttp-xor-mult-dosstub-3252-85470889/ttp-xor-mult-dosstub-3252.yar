rule TTP_XOR_MULT_DOSStub_3252 {
  strings:
    $key_3252 = { 66 3a [2] 12 22 [2] 55 20 [2] 12 31 [2] 5c 3d [2] 50 37 [2] 47 3c [2] 5c 72 [2] 61 }

  condition:
    any of them
}