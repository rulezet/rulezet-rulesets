rule TTP_XOR_MULT_DOSStub_1d76 {
  strings:
    $key_1d76 = { 49 1e [2] 3d 06 [2] 7a 04 [2] 3d 15 [2] 73 19 [2] 7f 13 [2] 68 18 [2] 73 56 [2] 4e }

  condition:
    any of them
}