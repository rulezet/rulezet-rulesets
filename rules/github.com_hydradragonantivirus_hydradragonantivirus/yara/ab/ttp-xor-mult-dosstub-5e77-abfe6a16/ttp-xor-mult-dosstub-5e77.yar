rule TTP_XOR_MULT_DOSStub_5e77 {
  strings:
    $key_5e77 = { 0a 1f [2] 7e 07 [2] 39 05 [2] 7e 14 [2] 30 18 [2] 3c 12 [2] 2b 19 [2] 30 57 [2] 0d }

  condition:
    any of them
}