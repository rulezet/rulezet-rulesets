rule TTP_XOR_MULT_DOSStub_3d50 {
  strings:
    $key_3d50 = { 69 38 [2] 1d 20 [2] 5a 22 [2] 1d 33 [2] 53 3f [2] 5f 35 [2] 48 3e [2] 53 70 [2] 6e }

  condition:
    any of them
}