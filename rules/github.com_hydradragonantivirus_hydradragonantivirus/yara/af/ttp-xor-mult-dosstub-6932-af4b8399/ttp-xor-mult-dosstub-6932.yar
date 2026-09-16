rule TTP_XOR_MULT_DOSStub_6932 {
  strings:
    $key_6932 = { 3d 5a [2] 49 42 [2] 0e 40 [2] 49 51 [2] 07 5d [2] 0b 57 [2] 1c 5c [2] 07 12 [2] 3a }

  condition:
    any of them
}