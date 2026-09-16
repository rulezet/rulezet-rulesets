rule TTP_XOR_MULT_DOSStub_4c77 {
  strings:
    $key_4c77 = { 18 1f [2] 6c 07 [2] 2b 05 [2] 6c 14 [2] 22 18 [2] 2e 12 [2] 39 19 [2] 22 57 [2] 1f }

  condition:
    any of them
}