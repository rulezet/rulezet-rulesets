rule TTP_XOR_MULT_DOSStub_1031 {
  strings:
    $key_1031 = { 44 59 [2] 30 41 [2] 77 43 [2] 30 52 [2] 7e 5e [2] 72 54 [2] 65 5f [2] 7e 11 [2] 43 }

  condition:
    any of them
}