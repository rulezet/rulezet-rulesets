rule TTP_XOR_MULT_DOSStub_6958 {
  strings:
    $key_6958 = { 3d 30 [2] 49 28 [2] 0e 2a [2] 49 3b [2] 07 37 [2] 0b 3d [2] 1c 36 [2] 07 78 [2] 3a }

  condition:
    any of them
}