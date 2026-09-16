rule TTP_XOR_MULT_DOSStub_0566 {
  strings:
    $key_0566 = { 51 0e [2] 25 16 [2] 62 14 [2] 25 05 [2] 6b 09 [2] 67 03 [2] 70 08 [2] 6b 46 [2] 56 }

  condition:
    any of them
}