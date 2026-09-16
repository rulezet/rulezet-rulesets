rule TTP_XOR_MULT_DOSStub_45e7 {
  strings:
    $key_45e7 = { 11 8f [2] 65 97 [2] 22 95 [2] 65 84 [2] 2b 88 [2] 27 82 [2] 30 89 [2] 2b c7 [2] 16 }

  condition:
    any of them
}