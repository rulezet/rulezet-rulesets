rule TTP_XOR_MULT_DOSStub_3d76 {
  strings:
    $key_3d76 = { 69 1e [2] 1d 06 [2] 5a 04 [2] 1d 15 [2] 53 19 [2] 5f 13 [2] 48 18 [2] 53 56 [2] 6e }

  condition:
    any of them
}