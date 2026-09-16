rule TTP_XOR_MULT_DOSStub_4066 {
  strings:
    $key_4066 = { 14 0e [2] 60 16 [2] 27 14 [2] 60 05 [2] 2e 09 [2] 22 03 [2] 35 08 [2] 2e 46 [2] 13 }

  condition:
    any of them
}