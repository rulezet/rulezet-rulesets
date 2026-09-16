rule TTP_XOR_MULT_DOSStub_6f77 {
  strings:
    $key_6f77 = { 3b 1f [2] 4f 07 [2] 08 05 [2] 4f 14 [2] 01 18 [2] 0d 12 [2] 1a 19 [2] 01 57 [2] 3c }

  condition:
    any of them
}