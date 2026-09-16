rule TTP_XOR_MULT_DOSStub_3de6 {
  strings:
    $key_3de6 = { 69 8e [2] 1d 96 [2] 5a 94 [2] 1d 85 [2] 53 89 [2] 5f 83 [2] 48 88 [2] 53 c6 [2] 6e }

  condition:
    any of them
}