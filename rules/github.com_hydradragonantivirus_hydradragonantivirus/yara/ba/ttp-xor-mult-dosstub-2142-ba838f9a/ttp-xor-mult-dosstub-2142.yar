rule TTP_XOR_MULT_DOSStub_2142 {
  strings:
    $key_2142 = { 75 2a [2] 01 32 [2] 46 30 [2] 01 21 [2] 4f 2d [2] 43 27 [2] 54 2c [2] 4f 62 [2] 72 }

  condition:
    any of them
}