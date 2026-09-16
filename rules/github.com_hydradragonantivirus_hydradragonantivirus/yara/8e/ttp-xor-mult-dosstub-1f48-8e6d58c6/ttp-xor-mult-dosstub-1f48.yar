rule TTP_XOR_MULT_DOSStub_1f48 {
  strings:
    $key_1f48 = { 4b 20 [2] 3f 38 [2] 78 3a [2] 3f 2b [2] 71 27 [2] 7d 2d [2] 6a 26 [2] 71 68 [2] 4c }

  condition:
    any of them
}