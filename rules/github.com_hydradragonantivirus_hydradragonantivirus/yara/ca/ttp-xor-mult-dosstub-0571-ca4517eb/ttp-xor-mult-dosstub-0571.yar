rule TTP_XOR_MULT_DOSStub_0571 {
  strings:
    $key_0571 = { 51 19 [2] 25 01 [2] 62 03 [2] 25 12 [2] 6b 1e [2] 67 14 [2] 70 1f [2] 6b 51 [2] 56 }

  condition:
    any of them
}