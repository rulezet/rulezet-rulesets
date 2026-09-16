rule TTP_XOR_MULT_DOSStub_6552 {
  strings:
    $key_6552 = { 31 3a [2] 45 22 [2] 02 20 [2] 45 31 [2] 0b 3d [2] 07 37 [2] 10 3c [2] 0b 72 [2] 36 }

  condition:
    any of them
}