rule TTP_XOR_MULT_DOSStub_2b77 {
  strings:
    $key_2b77 = { 7f 1f [2] 0b 07 [2] 4c 05 [2] 0b 14 [2] 45 18 [2] 49 12 [2] 5e 19 [2] 45 57 [2] 78 }

  condition:
    any of them
}