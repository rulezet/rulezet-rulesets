rule TTP_XOR_MULT_DOSStub_6630 {
  strings:
    $key_6630 = { 32 58 [2] 46 40 [2] 01 42 [2] 46 53 [2] 08 5f [2] 04 55 [2] 13 5e [2] 08 10 [2] 35 }

  condition:
    any of them
}