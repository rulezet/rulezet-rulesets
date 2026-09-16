rule TTP_XOR_MULT_DOSStub_3770 {
  strings:
    $key_3770 = { 63 18 [2] 17 00 [2] 50 02 [2] 17 13 [2] 59 1f [2] 55 15 [2] 42 1e [2] 59 50 [2] 64 }

  condition:
    any of them
}