rule TTP_XOR_MULT_DOSStub_50e6 {
  strings:
    $key_50e6 = { 04 8e [2] 70 96 [2] 37 94 [2] 70 85 [2] 3e 89 [2] 32 83 [2] 25 88 [2] 3e c6 [2] 03 }

  condition:
    any of them
}