rule TTP_XOR_MULT_DOSStub_6170 {
  strings:
    $key_6170 = { 35 18 [2] 41 00 [2] 06 02 [2] 41 13 [2] 0f 1f [2] 03 15 [2] 14 1e [2] 0f 50 [2] 32 }

  condition:
    any of them
}