rule TTP_XOR_MULT_DOSStub_2842 {
  strings:
    $key_2842 = { 7c 2a [2] 08 32 [2] 4f 30 [2] 08 21 [2] 46 2d [2] 4a 27 [2] 5d 2c [2] 46 62 [2] 7b }

  condition:
    any of them
}