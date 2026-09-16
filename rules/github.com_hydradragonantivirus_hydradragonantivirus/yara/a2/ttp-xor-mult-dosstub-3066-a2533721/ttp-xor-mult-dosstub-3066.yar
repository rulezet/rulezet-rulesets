rule TTP_XOR_MULT_DOSStub_3066 {
  strings:
    $key_3066 = { 64 0e [2] 10 16 [2] 57 14 [2] 10 05 [2] 5e 09 [2] 52 03 [2] 45 08 [2] 5e 46 [2] 63 }

  condition:
    any of them
}