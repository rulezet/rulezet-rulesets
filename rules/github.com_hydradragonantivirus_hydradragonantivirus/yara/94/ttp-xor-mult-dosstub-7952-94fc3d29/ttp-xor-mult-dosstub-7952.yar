rule TTP_XOR_MULT_DOSStub_7952 {
  strings:
    $key_7952 = { 2d 3a [2] 59 22 [2] 1e 20 [2] 59 31 [2] 17 3d [2] 1b 37 [2] 0c 3c [2] 17 72 [2] 2a }

  condition:
    any of them
}