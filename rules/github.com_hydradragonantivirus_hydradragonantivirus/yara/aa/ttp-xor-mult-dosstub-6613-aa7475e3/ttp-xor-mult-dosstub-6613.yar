rule TTP_XOR_MULT_DOSStub_6613 {
  strings:
    $key_6613 = { 32 7b [2] 46 63 [2] 01 61 [2] 46 70 [2] 08 7c [2] 04 76 [2] 13 7d [2] 08 33 [2] 35 }

  condition:
    any of them
}