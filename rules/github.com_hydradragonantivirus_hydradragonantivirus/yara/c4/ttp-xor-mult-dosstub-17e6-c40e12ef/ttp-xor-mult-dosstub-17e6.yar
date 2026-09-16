rule TTP_XOR_MULT_DOSStub_17e6 {
  strings:
    $key_17e6 = { 43 8e [2] 37 96 [2] 70 94 [2] 37 85 [2] 79 89 [2] 75 83 [2] 62 88 [2] 79 c6 [2] 44 }

  condition:
    any of them
}