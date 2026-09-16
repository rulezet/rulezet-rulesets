rule TTP_XOR_MULT_DOSStub_3d70 {
  strings:
    $key_3d70 = { 69 18 [2] 1d 00 [2] 5a 02 [2] 1d 13 [2] 53 1f [2] 5f 15 [2] 48 1e [2] 53 50 [2] 6e }

  condition:
    any of them
}