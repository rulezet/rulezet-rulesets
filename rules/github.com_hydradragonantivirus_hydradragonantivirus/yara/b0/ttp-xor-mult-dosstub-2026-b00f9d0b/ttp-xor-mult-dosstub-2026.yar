rule TTP_XOR_MULT_DOSStub_2026 {
  strings:
    $key_2026 = { 74 4e [2] 00 56 [2] 47 54 [2] 00 45 [2] 4e 49 [2] 42 43 [2] 55 48 [2] 4e 06 [2] 73 }

  condition:
    any of them
}