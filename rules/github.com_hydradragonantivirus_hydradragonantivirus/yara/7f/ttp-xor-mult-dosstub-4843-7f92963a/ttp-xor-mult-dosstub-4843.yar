rule TTP_XOR_MULT_DOSStub_4843 {
  strings:
    $key_4843 = { 1c 2b [2] 68 33 [2] 2f 31 [2] 68 20 [2] 26 2c [2] 2a 26 [2] 3d 2d [2] 26 63 [2] 1b }

  condition:
    any of them
}