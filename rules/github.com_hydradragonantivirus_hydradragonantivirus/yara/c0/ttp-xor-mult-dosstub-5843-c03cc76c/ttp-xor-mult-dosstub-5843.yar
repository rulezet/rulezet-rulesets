rule TTP_XOR_MULT_DOSStub_5843 {
  strings:
    $key_5843 = { 0c 2b [2] 78 33 [2] 3f 31 [2] 78 20 [2] 36 2c [2] 3a 26 [2] 2d 2d [2] 36 63 [2] 0b }

  condition:
    any of them
}