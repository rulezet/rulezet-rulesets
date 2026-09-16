rule TTP_XOR_MULT_DOSStub_0f77 {
  strings:
    $key_0f77 = { 5b 1f [2] 2f 07 [2] 68 05 [2] 2f 14 [2] 61 18 [2] 6d 12 [2] 7a 19 [2] 61 57 [2] 5c }

  condition:
    any of them
}