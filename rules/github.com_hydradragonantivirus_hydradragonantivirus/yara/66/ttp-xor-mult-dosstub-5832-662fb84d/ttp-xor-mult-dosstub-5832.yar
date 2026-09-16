rule TTP_XOR_MULT_DOSStub_5832 {
  strings:
    $key_5832 = { 0c 5a [2] 78 42 [2] 3f 40 [2] 78 51 [2] 36 5d [2] 3a 57 [2] 2d 5c [2] 36 12 [2] 0b }

  condition:
    any of them
}