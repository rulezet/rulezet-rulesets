rule TTP_XOR_MULT_DOSStub_0d52 {
  strings:
    $key_0d52 = { 59 3a [2] 2d 22 [2] 6a 20 [2] 2d 31 [2] 63 3d [2] 6f 37 [2] 78 3c [2] 63 72 [2] 5e }

  condition:
    any of them
}