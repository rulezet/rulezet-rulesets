rule TTP_XOR_MULT_DOSStub_3270 {
  strings:
    $key_3270 = { 66 18 [2] 12 00 [2] 55 02 [2] 12 13 [2] 5c 1f [2] 50 15 [2] 47 1e [2] 5c 50 [2] 61 }

  condition:
    any of them
}