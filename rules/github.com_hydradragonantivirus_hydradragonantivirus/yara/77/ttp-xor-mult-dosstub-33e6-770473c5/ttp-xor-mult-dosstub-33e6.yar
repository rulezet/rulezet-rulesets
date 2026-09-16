rule TTP_XOR_MULT_DOSStub_33e6 {
  strings:
    $key_33e6 = { 67 8e [2] 13 96 [2] 54 94 [2] 13 85 [2] 5d 89 [2] 51 83 [2] 46 88 [2] 5d c6 [2] 60 }

  condition:
    any of them
}