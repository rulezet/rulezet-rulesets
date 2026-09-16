rule TTP_XOR_MULT_DOSStub_7660 {
  strings:
    $key_7660 = { 22 08 [2] 56 10 [2] 11 12 [2] 56 03 [2] 18 0f [2] 14 05 [2] 03 0e [2] 18 40 [2] 25 }

  condition:
    any of them
}