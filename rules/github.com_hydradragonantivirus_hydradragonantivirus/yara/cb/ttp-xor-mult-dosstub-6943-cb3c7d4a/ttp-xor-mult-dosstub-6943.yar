rule TTP_XOR_MULT_DOSStub_6943 {
  strings:
    $key_6943 = { 3d 2b [2] 49 33 [2] 0e 31 [2] 49 20 [2] 07 2c [2] 0b 26 [2] 1c 2d [2] 07 63 [2] 3a }

  condition:
    any of them
}