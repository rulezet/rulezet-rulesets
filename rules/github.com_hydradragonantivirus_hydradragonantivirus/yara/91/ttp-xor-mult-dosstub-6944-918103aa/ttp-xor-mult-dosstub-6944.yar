rule TTP_XOR_MULT_DOSStub_6944 {
  strings:
    $key_6944 = { 3d 2c [2] 49 34 [2] 0e 36 [2] 49 27 [2] 07 2b [2] 0b 21 [2] 1c 2a [2] 07 64 [2] 3a }

  condition:
    any of them
}