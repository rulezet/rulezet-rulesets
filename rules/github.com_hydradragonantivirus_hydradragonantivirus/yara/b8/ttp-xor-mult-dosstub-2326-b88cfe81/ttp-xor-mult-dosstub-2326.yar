rule TTP_XOR_MULT_DOSStub_2326 {
  strings:
    $key_2326 = { 77 4e [2] 03 56 [2] 44 54 [2] 03 45 [2] 4d 49 [2] 41 43 [2] 56 48 [2] 4d 06 [2] 70 }

  condition:
    any of them
}