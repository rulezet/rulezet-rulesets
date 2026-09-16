rule TTP_XOR_MULT_DOSStub_6977 {
  strings:
    $key_6977 = { 3d 1f [2] 49 07 [2] 0e 05 [2] 49 14 [2] 07 18 [2] 0b 12 [2] 1c 19 [2] 07 57 [2] 3a }

  condition:
    any of them
}