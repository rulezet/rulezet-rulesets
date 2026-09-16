rule TTP_XOR_MULT_DOSStub_6d52 {
  strings:
    $key_6d52 = { 39 3a [2] 4d 22 [2] 0a 20 [2] 4d 31 [2] 03 3d [2] 0f 37 [2] 18 3c [2] 03 72 [2] 3e }

  condition:
    any of them
}