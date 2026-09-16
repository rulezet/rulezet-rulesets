rule TTP_XOR_MULT_DOSStub_5052 {
  strings:
    $key_5052 = { 04 3a [2] 70 22 [2] 37 20 [2] 70 31 [2] 3e 3d [2] 32 37 [2] 25 3c [2] 3e 72 [2] 03 }

  condition:
    any of them
}