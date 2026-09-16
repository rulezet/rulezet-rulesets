rule TTP_XOR_MULT_DOSStub_52e6 {
  strings:
    $key_52e6 = { 06 8e [2] 72 96 [2] 35 94 [2] 72 85 [2] 3c 89 [2] 30 83 [2] 27 88 [2] 3c c6 [2] 01 }

  condition:
    any of them
}