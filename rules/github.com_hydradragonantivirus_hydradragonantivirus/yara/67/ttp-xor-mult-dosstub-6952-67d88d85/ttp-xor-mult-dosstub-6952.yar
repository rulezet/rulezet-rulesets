rule TTP_XOR_MULT_DOSStub_6952 {
  strings:
    $key_6952 = { 3d 3a [2] 49 22 [2] 0e 20 [2] 49 31 [2] 07 3d [2] 0b 37 [2] 1c 3c [2] 07 72 [2] 3a }

  condition:
    any of them
}