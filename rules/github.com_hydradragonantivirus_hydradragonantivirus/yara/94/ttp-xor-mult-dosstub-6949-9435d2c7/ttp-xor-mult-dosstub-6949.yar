rule TTP_XOR_MULT_DOSStub_6949 {
  strings:
    $key_6949 = { 3d 21 [2] 49 39 [2] 0e 3b [2] 49 2a [2] 07 26 [2] 0b 2c [2] 1c 27 [2] 07 69 [2] 3a }

  condition:
    any of them
}