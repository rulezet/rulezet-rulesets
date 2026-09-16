rule TTP_XOR_MULT_DOSStub_3570 {
  strings:
    $key_3570 = { 61 18 [2] 15 00 [2] 52 02 [2] 15 13 [2] 5b 1f [2] 57 15 [2] 40 1e [2] 5b 50 [2] 66 }

  condition:
    any of them
}