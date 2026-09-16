rule TTP_XOR_MULT_DOSStub_4742 {
  strings:
    $key_4742 = { 13 2a [2] 67 32 [2] 20 30 [2] 67 21 [2] 29 2d [2] 25 27 [2] 32 2c [2] 29 62 [2] 14 }

  condition:
    any of them
}