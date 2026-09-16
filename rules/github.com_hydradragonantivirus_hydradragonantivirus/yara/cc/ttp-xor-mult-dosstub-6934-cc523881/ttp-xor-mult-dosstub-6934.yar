rule TTP_XOR_MULT_DOSStub_6934 {
  strings:
    $key_6934 = { 3d 5c [2] 49 44 [2] 0e 46 [2] 49 57 [2] 07 5b [2] 0b 51 [2] 1c 5a [2] 07 14 [2] 3a }

  condition:
    any of them
}