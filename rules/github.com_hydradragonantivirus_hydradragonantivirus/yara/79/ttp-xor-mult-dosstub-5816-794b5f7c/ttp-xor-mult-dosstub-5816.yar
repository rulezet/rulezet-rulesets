rule TTP_XOR_MULT_DOSStub_5816 {
  strings:
    $key_5816 = { 0c 7e [2] 78 66 [2] 3f 64 [2] 78 75 [2] 36 79 [2] 3a 73 [2] 2d 78 [2] 36 36 [2] 0b }

  condition:
    any of them
}