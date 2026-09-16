rule TTP_XOR_MULT_DOSStub_6641 {
  strings:
    $key_6641 = { 32 29 [2] 46 31 [2] 01 33 [2] 46 22 [2] 08 2e [2] 04 24 [2] 13 2f [2] 08 61 [2] 35 }

  condition:
    any of them
}