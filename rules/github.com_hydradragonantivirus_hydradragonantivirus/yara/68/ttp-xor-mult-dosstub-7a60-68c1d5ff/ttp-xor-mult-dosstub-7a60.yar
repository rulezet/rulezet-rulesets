rule TTP_XOR_MULT_DOSStub_7a60 {
  strings:
    $key_7a60 = { 2e 08 [2] 5a 10 [2] 1d 12 [2] 5a 03 [2] 14 0f [2] 18 05 [2] 0f 0e [2] 14 40 [2] 29 }

  condition:
    any of them
}