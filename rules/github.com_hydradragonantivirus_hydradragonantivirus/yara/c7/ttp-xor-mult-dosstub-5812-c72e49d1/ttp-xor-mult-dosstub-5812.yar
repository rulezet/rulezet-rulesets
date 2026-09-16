rule TTP_XOR_MULT_DOSStub_5812 {
  strings:
    $key_5812 = { 0c 7a [2] 78 62 [2] 3f 60 [2] 78 71 [2] 36 7d [2] 3a 77 [2] 2d 7c [2] 36 32 [2] 0b }

  condition:
    any of them
}