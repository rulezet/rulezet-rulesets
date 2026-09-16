rule TTP_XOR_MULT_DOSStub_7c77 {
  strings:
    $key_7c77 = { 28 1f [2] 5c 07 [2] 1b 05 [2] 5c 14 [2] 12 18 [2] 1e 12 [2] 09 19 [2] 12 57 [2] 2f }

  condition:
    any of them
}