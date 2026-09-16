rule TTP_XOR_MULT_DOSStub_2d52 {
  strings:
    $key_2d52 = { 79 3a [2] 0d 22 [2] 4a 20 [2] 0d 31 [2] 43 3d [2] 4f 37 [2] 58 3c [2] 43 72 [2] 7e }

  condition:
    any of them
}