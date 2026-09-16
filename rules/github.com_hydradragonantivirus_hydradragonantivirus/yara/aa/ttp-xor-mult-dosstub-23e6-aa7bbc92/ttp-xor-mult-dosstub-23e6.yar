rule TTP_XOR_MULT_DOSStub_23e6 {
  strings:
    $key_23e6 = { 77 8e [2] 03 96 [2] 44 94 [2] 03 85 [2] 4d 89 [2] 41 83 [2] 56 88 [2] 4d c6 [2] 70 }

  condition:
    any of them
}