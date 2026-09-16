rule TTP_XOR_MULT_DOSStub_6a42 {
  strings:
    $key_6a42 = { 3e 2a [2] 4a 32 [2] 0d 30 [2] 4a 21 [2] 04 2d [2] 08 27 [2] 1f 2c [2] 04 62 [2] 39 }

  condition:
    any of them
}