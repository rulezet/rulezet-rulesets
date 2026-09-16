rule TTP_XOR_MULT_DOSStub_5838 {
  strings:
    $key_5838 = { 0c 50 [2] 78 48 [2] 3f 4a [2] 78 5b [2] 36 57 [2] 3a 5d [2] 2d 56 [2] 36 18 [2] 0b }

  condition:
    any of them
}