rule TTP_XOR_MULT_DOSStub_5833 {
  strings:
    $key_5833 = { 0c 5b [2] 78 43 [2] 3f 41 [2] 78 50 [2] 36 5c [2] 3a 56 [2] 2d 5d [2] 36 13 [2] 0b }

  condition:
    any of them
}