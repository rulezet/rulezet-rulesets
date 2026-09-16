rule TTP_XOR_MULT_DOSStub_3d56 {
  strings:
    $key_3d56 = { 69 3e [2] 1d 26 [2] 5a 24 [2] 1d 35 [2] 53 39 [2] 5f 33 [2] 48 38 [2] 53 76 [2] 6e }

  condition:
    any of them
}