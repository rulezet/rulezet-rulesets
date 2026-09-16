rule TTP_XOR_MULT_DOSStub_1c77 {
  strings:
    $key_1c77 = { 48 1f [2] 3c 07 [2] 7b 05 [2] 3c 14 [2] 72 18 [2] 7e 12 [2] 69 19 [2] 72 57 [2] 4f }

  condition:
    any of them
}