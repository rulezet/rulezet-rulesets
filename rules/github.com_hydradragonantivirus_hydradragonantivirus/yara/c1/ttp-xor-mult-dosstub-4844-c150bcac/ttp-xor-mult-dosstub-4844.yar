rule TTP_XOR_MULT_DOSStub_4844 {
  strings:
    $key_4844 = { 1c 2c [2] 68 34 [2] 2f 36 [2] 68 27 [2] 26 2b [2] 2a 21 [2] 3d 2a [2] 26 64 [2] 1b }

  condition:
    any of them
}