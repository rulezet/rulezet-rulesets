rule TTP_XOR_MULT_DOSStub_2f77 {
  strings:
    $key_2f77 = { 7b 1f [2] 0f 07 [2] 48 05 [2] 0f 14 [2] 41 18 [2] 4d 12 [2] 5a 19 [2] 41 57 [2] 7c }

  condition:
    any of them
}