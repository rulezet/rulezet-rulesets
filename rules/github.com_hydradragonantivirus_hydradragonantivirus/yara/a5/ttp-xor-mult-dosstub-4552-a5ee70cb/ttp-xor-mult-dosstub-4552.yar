rule TTP_XOR_MULT_DOSStub_4552 {
  strings:
    $key_4552 = { 11 3a [2] 65 22 [2] 22 20 [2] 65 31 [2] 2b 3d [2] 27 37 [2] 30 3c [2] 2b 72 [2] 16 }

  condition:
    any of them
}