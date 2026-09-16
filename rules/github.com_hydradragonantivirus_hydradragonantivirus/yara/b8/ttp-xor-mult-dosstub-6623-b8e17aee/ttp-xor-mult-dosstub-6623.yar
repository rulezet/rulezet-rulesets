rule TTP_XOR_MULT_DOSStub_6623 {
  strings:
    $key_6623 = { 32 4b [2] 46 53 [2] 01 51 [2] 46 40 [2] 08 4c [2] 04 46 [2] 13 4d [2] 08 03 [2] 35 }

  condition:
    any of them
}