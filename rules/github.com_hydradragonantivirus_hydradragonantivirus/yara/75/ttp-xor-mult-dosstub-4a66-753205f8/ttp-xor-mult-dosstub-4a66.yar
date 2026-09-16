rule TTP_XOR_MULT_DOSStub_4a66 {
  strings:
    $key_4a66 = { 1e 0e [2] 6a 16 [2] 2d 14 [2] 6a 05 [2] 24 09 [2] 28 03 [2] 3f 08 [2] 24 46 [2] 19 }

  condition:
    any of them
}