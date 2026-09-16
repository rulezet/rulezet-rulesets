rule TTP_XOR_MULT_DOSStub_6670 {
  strings:
    $key_6670 = { 32 18 [2] 46 00 [2] 01 02 [2] 46 13 [2] 08 1f [2] 04 15 [2] 13 1e [2] 08 50 [2] 35 }

  condition:
    any of them
}