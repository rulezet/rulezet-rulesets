rule TTP_XOR_MULT_DOSStub_7521 {
  strings:
    $key_7521 = { 21 49 [2] 55 51 [2] 12 53 [2] 55 42 [2] 1b 4e [2] 17 44 [2] 00 4f [2] 1b 01 [2] 26 }

  condition:
    any of them
}