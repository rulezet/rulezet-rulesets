rule TTP_XOR_MULT_DOSStub_1152 {
  strings:
    $key_1152 = { 45 3a [2] 31 22 [2] 76 20 [2] 31 31 [2] 7f 3d [2] 73 37 [2] 64 3c [2] 7f 72 [2] 42 }

  condition:
    any of them
}