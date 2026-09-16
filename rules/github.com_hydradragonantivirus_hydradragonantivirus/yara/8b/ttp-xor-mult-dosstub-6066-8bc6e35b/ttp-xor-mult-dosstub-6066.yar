rule TTP_XOR_MULT_DOSStub_6066 {
  strings:
    $key_6066 = { 34 0e [2] 40 16 [2] 07 14 [2] 40 05 [2] 0e 09 [2] 02 03 [2] 15 08 [2] 0e 46 [2] 33 }

  condition:
    any of them
}