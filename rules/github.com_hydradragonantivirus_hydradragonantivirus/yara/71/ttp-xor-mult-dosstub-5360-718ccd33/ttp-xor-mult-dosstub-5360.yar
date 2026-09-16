rule TTP_XOR_MULT_DOSStub_5360 {
  strings:
    $key_5360 = { 07 08 [2] 73 10 [2] 34 12 [2] 73 03 [2] 3d 0f [2] 31 05 [2] 26 0e [2] 3d 40 [2] 00 }

  condition:
    any of them
}