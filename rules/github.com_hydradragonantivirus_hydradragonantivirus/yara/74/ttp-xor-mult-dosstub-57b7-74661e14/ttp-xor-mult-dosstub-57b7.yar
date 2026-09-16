rule TTP_XOR_MULT_DOSStub_57b7 {
  strings:
    $key_57b7 = { 03 df [2] 77 c7 [2] 30 c5 [2] 77 d4 [2] 39 d8 [2] 35 d2 [2] 22 d9 [2] 39 97 [2] 04 }

  condition:
    any of them
}