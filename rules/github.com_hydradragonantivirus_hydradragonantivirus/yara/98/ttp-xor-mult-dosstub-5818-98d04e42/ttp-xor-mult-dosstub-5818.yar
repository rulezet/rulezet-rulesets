rule TTP_XOR_MULT_DOSStub_5818 {
  strings:
    $key_5818 = { 0c 70 [2] 78 68 [2] 3f 6a [2] 78 7b [2] 36 77 [2] 3a 7d [2] 2d 76 [2] 36 38 [2] 0b }

  condition:
    any of them
}