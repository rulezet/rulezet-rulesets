rule TTP_XOR_MULT_DOSStub_1d46 {
  strings:
    $key_1d46 = { 49 2e [2] 3d 36 [2] 7a 34 [2] 3d 25 [2] 73 29 [2] 7f 23 [2] 68 28 [2] 73 66 [2] 4e }

  condition:
    any of them
}