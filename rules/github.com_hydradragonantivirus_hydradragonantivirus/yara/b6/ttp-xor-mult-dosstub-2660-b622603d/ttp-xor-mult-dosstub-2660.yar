rule TTP_XOR_MULT_DOSStub_2660 {
  strings:
    $key_2660 = { 72 08 [2] 06 10 [2] 41 12 [2] 06 03 [2] 48 0f [2] 44 05 [2] 53 0e [2] 48 40 [2] 75 }

  condition:
    any of them
}