rule TTP_XOR_MULT_DOSStub_3652 {
  strings:
    $key_3652 = { 62 3a [2] 16 22 [2] 51 20 [2] 16 31 [2] 58 3d [2] 54 37 [2] 43 3c [2] 58 72 [2] 65 }

  condition:
    any of them
}