rule TTP_XOR_MULT_DOSStub_4d52 {
  strings:
    $key_4d52 = { 19 3a [2] 6d 22 [2] 2a 20 [2] 6d 31 [2] 23 3d [2] 2f 37 [2] 38 3c [2] 23 72 [2] 1e }

  condition:
    any of them
}