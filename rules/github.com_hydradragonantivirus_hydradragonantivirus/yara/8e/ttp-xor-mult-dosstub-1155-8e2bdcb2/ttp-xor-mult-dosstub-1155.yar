rule TTP_XOR_MULT_DOSStub_1155 {
  strings:
    $key_1155 = { 45 3d [2] 31 25 [2] 76 27 [2] 31 36 [2] 7f 3a [2] 73 30 [2] 64 3b [2] 7f 75 [2] 42 }

  condition:
    any of them
}