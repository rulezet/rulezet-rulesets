rule TTP_XOR_MULT_DOSStub_5822 {
  strings:
    $key_5822 = { 0c 4a [2] 78 52 [2] 3f 50 [2] 78 41 [2] 36 4d [2] 3a 47 [2] 2d 4c [2] 36 02 [2] 0b }

  condition:
    any of them
}