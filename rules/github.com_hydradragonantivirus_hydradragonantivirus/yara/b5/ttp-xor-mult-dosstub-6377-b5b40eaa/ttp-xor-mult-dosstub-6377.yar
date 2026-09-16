rule TTP_XOR_MULT_DOSStub_6377 {
  strings:
    $key_6377 = { 37 1f [2] 43 07 [2] 04 05 [2] 43 14 [2] 0d 18 [2] 01 12 [2] 16 19 [2] 0d 57 [2] 30 }

  condition:
    any of them
}