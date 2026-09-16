rule TTP_XOR_MULT_DOSStub_3d66 {
  strings:
    $key_3d66 = { 69 0e [2] 1d 16 [2] 5a 14 [2] 1d 05 [2] 53 09 [2] 5f 03 [2] 48 08 [2] 53 46 [2] 6e }

  condition:
    any of them
}