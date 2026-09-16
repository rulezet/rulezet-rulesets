rule TTP_XOR_MULT_DOSStub_13e6 {
  strings:
    $key_13e6 = { 47 8e [2] 33 96 [2] 74 94 [2] 33 85 [2] 7d 89 [2] 71 83 [2] 66 88 [2] 7d c6 [2] 40 }

  condition:
    any of them
}