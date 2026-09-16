rule TTP_XOR_MULT_DOSStub_69e2 {
  strings:
    $key_69e2 = { 3d 8a [2] 49 92 [2] 0e 90 [2] 49 81 [2] 07 8d [2] 0b 87 [2] 1c 8c [2] 07 c2 [2] 3a }

  condition:
    any of them
}