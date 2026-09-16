rule TTP_XOR_MULT_DOSStub_0552 {
  strings:
    $key_0552 = { 51 3a [2] 25 22 [2] 62 20 [2] 25 31 [2] 6b 3d [2] 67 37 [2] 70 3c [2] 6b 72 [2] 56 }

  condition:
    any of them
}