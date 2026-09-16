rule TTP_XOR_MULT_DOSStub_16e6 {
  strings:
    $key_16e6 = { 42 8e [2] 36 96 [2] 71 94 [2] 36 85 [2] 78 89 [2] 74 83 [2] 63 88 [2] 78 c6 [2] 45 }

  condition:
    any of them
}