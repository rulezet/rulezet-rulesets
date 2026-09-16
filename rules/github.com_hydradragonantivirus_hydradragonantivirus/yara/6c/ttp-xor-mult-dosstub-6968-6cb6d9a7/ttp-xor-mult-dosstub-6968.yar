rule TTP_XOR_MULT_DOSStub_6968 {
  strings:
    $key_6968 = { 3d 00 [2] 49 18 [2] 0e 1a [2] 49 0b [2] 07 07 [2] 0b 0d [2] 1c 06 [2] 07 48 [2] 3a }

  condition:
    any of them
}