rule TTP_XOR_MULT_DOSStub_6760 {
  strings:
    $key_6760 = { 33 08 [2] 47 10 [2] 00 12 [2] 47 03 [2] 09 0f [2] 05 05 [2] 12 0e [2] 09 40 [2] 34 }

  condition:
    any of them
}