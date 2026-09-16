rule TTP_XOR_MULT_DOSStub_1026 {
  strings:
    $key_1026 = { 44 4e [2] 30 56 [2] 77 54 [2] 30 45 [2] 7e 49 [2] 72 43 [2] 65 48 [2] 7e 06 [2] 43 }

  condition:
    any of them
}