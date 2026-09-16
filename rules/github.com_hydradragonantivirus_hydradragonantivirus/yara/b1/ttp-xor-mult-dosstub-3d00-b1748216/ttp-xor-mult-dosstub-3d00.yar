rule TTP_XOR_MULT_DOSStub_3d00 {
  strings:
    $key_3d00 = { 69 68 [2] 1d 70 [2] 5a 72 [2] 1d 63 [2] 53 6f [2] 5f 65 [2] 48 6e [2] 53 20 [2] 6e }

  condition:
    any of them
}