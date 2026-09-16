rule TTP_XOR_MULT_DOSStub_6731 {
  strings:
    $key_6731 = { 33 59 [2] 47 41 [2] 00 43 [2] 47 52 [2] 09 5e [2] 05 54 [2] 12 5f [2] 09 11 [2] 34 }

  condition:
    any of them
}