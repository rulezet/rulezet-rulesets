rule TTP_XOR_MULT_DOSStub_1d70 {
  strings:
    $key_1d70 = { 49 18 [2] 3d 00 [2] 7a 02 [2] 3d 13 [2] 73 1f [2] 7f 15 [2] 68 1e [2] 73 50 [2] 4e }

  condition:
    any of them
}