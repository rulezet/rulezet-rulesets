rule TTP_XOR_MULT_DOSStub_3d41 {
  strings:
    $key_3d41 = { 69 29 [2] 1d 31 [2] 5a 33 [2] 1d 22 [2] 53 2e [2] 5f 24 [2] 48 2f [2] 53 61 [2] 6e }

  condition:
    any of them
}