rule TTP_XOR_MULT_DOSStub_3d20 {
  strings:
    $key_3d20 = { 69 48 [2] 1d 50 [2] 5a 52 [2] 1d 43 [2] 53 4f [2] 5f 45 [2] 48 4e [2] 53 00 [2] 6e }

  condition:
    any of them
}