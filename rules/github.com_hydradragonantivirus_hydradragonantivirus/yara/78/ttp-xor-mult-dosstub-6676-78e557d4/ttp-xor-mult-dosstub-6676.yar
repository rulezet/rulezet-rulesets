rule TTP_XOR_MULT_DOSStub_6676 {
  strings:
    $key_6676 = { 32 1e [2] 46 06 [2] 01 04 [2] 46 15 [2] 08 19 [2] 04 13 [2] 13 18 [2] 08 56 [2] 35 }

  condition:
    any of them
}