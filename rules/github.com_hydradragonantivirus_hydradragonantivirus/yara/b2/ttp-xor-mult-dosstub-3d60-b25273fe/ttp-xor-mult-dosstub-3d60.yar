rule TTP_XOR_MULT_DOSStub_3d60 {
  strings:
    $key_3d60 = { 69 08 [2] 1d 10 [2] 5a 12 [2] 1d 03 [2] 53 0f [2] 5f 05 [2] 48 0e [2] 53 40 [2] 6e }

  condition:
    any of them
}