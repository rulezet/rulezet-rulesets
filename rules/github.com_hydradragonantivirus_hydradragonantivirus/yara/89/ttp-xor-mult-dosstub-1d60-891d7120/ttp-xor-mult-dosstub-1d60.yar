rule TTP_XOR_MULT_DOSStub_1d60 {
  strings:
    $key_1d60 = { 49 08 [2] 3d 10 [2] 7a 12 [2] 3d 03 [2] 73 0f [2] 7f 05 [2] 68 0e [2] 73 40 [2] 4e }

  condition:
    any of them
}