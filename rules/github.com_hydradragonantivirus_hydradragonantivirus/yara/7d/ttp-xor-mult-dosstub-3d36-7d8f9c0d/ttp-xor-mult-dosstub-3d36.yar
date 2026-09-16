rule TTP_XOR_MULT_DOSStub_3d36 {
  strings:
    $key_3d36 = { 69 5e [2] 1d 46 [2] 5a 44 [2] 1d 55 [2] 53 59 [2] 5f 53 [2] 48 58 [2] 53 16 [2] 6e }

  condition:
    any of them
}