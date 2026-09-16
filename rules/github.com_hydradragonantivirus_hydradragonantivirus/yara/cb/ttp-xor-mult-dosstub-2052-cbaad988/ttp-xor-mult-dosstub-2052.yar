rule TTP_XOR_MULT_DOSStub_2052 {
  strings:
    $key_2052 = { 74 3a [2] 00 22 [2] 47 20 [2] 00 31 [2] 4e 3d [2] 42 37 [2] 55 3c [2] 4e 72 [2] 73 }

  condition:
    any of them
}