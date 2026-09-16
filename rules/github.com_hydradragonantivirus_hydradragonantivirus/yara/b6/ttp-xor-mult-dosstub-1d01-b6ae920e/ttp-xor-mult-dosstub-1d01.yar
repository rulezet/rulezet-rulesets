rule TTP_XOR_MULT_DOSStub_1d01 {
  strings:
    $key_1d01 = { 49 69 [2] 3d 71 [2] 7a 73 [2] 3d 62 [2] 73 6e [2] 7f 64 [2] 68 6f [2] 73 21 [2] 4e }

  condition:
    any of them
}