rule TTP_XOR_MULT_DOSStub_57e6 {
  strings:
    $key_57e6 = { 03 8e [2] 77 96 [2] 30 94 [2] 77 85 [2] 39 89 [2] 35 83 [2] 22 88 [2] 39 c6 [2] 04 }

  condition:
    any of them
}