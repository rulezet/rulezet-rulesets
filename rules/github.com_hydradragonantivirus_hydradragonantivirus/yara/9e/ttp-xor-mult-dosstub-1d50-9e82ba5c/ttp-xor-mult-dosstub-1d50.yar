rule TTP_XOR_MULT_DOSStub_1d50 {
  strings:
    $key_1d50 = { 49 38 [2] 3d 20 [2] 7a 22 [2] 3d 33 [2] 73 3f [2] 7f 35 [2] 68 3e [2] 73 70 [2] 4e }

  condition:
    any of them
}