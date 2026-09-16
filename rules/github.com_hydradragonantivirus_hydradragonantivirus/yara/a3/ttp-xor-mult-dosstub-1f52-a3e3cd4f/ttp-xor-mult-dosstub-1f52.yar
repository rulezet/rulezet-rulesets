rule TTP_XOR_MULT_DOSStub_1f52 {
  strings:
    $key_1f52 = { 4b 3a [2] 3f 22 [2] 78 20 [2] 3f 31 [2] 71 3d [2] 7d 37 [2] 6a 3c [2] 71 72 [2] 4c }

  condition:
    any of them
}