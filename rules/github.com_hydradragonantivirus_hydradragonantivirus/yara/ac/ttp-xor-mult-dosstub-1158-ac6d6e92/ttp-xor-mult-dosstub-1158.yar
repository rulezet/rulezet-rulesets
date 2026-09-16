rule TTP_XOR_MULT_DOSStub_1158 {
  strings:
    $key_1158 = { 45 30 [2] 31 28 [2] 76 2a [2] 31 3b [2] 7f 37 [2] 73 3d [2] 64 36 [2] 7f 78 [2] 42 }

  condition:
    any of them
}