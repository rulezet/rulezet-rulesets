rule TTP_XOR_MULT_DOSStub_4521 {
  strings:
    $key_4521 = { 11 49 [2] 65 51 [2] 22 53 [2] 65 42 [2] 2b 4e [2] 27 44 [2] 30 4f [2] 2b 01 [2] 16 }

  condition:
    any of them
}