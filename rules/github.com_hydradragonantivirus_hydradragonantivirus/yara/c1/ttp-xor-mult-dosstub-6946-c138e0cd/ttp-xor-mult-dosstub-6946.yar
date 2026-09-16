rule TTP_XOR_MULT_DOSStub_6946 {
  strings:
    $key_6946 = { 3d 2e [2] 49 36 [2] 0e 34 [2] 49 25 [2] 07 29 [2] 0b 23 [2] 1c 28 [2] 07 66 [2] 3a }

  condition:
    any of them
}