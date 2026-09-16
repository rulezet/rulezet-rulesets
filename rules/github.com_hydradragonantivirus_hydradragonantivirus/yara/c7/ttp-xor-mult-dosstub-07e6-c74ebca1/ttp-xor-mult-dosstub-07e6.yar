rule TTP_XOR_MULT_DOSStub_07e6 {
  strings:
    $key_07e6 = { 53 8e [2] 27 96 [2] 60 94 [2] 27 85 [2] 69 89 [2] 65 83 [2] 72 88 [2] 69 c6 [2] 54 }

  condition:
    any of them
}