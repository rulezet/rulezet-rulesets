rule TTP_XOR_MULT_DOSStub_30e6 {
  strings:
    $key_30e6 = { 64 8e [2] 10 96 [2] 57 94 [2] 10 85 [2] 5e 89 [2] 52 83 [2] 45 88 [2] 5e c6 [2] 63 }

  condition:
    any of them
}