rule TTP_XOR_MULT_DOSStub_1f55 {
  strings:
    $key_1f55 = { 4b 3d [2] 3f 25 [2] 78 27 [2] 3f 36 [2] 71 3a [2] 7d 30 [2] 6a 3b [2] 71 75 [2] 4c }

  condition:
    any of them
}