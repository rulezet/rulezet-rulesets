rule TTP_XOR_MULT_DOSStub_1d47 {
  strings:
    $key_1d47 = { 49 2f [2] 3d 37 [2] 7a 35 [2] 3d 24 [2] 73 28 [2] 7f 22 [2] 68 29 [2] 73 67 [2] 4e }

  condition:
    any of them
}