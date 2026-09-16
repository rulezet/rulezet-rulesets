rule TTP_XOR_MULT_DOSStub_1d26 {
  strings:
    $key_1d26 = { 49 4e [2] 3d 56 [2] 7a 54 [2] 3d 45 [2] 73 49 [2] 7f 43 [2] 68 48 [2] 73 06 [2] 4e }

  condition:
    any of them
}