rule TTP_XOR_MULT_DOSStub_6625 {
  strings:
    $key_6625 = { 32 4d [2] 46 55 [2] 01 57 [2] 46 46 [2] 08 4a [2] 04 40 [2] 13 4b [2] 08 05 [2] 35 }

  condition:
    any of them
}