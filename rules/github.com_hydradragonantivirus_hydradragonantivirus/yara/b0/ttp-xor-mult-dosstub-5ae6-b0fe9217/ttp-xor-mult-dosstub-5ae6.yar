rule TTP_XOR_MULT_DOSStub_5ae6 {
  strings:
    $key_5ae6 = { 0e 8e [2] 7a 96 [2] 3d 94 [2] 7a 85 [2] 34 89 [2] 38 83 [2] 2f 88 [2] 34 c6 [2] 09 }

  condition:
    any of them
}