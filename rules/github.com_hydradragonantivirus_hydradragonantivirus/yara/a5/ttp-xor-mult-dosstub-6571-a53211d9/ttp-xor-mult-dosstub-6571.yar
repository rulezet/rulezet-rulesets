rule TTP_XOR_MULT_DOSStub_6571 {
  strings:
    $key_6571 = { 31 19 [2] 45 01 [2] 02 03 [2] 45 12 [2] 0b 1e [2] 07 14 [2] 10 1f [2] 0b 51 [2] 36 }

  condition:
    any of them
}