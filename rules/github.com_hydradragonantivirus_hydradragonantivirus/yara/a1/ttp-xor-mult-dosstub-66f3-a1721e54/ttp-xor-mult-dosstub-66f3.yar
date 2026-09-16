rule TTP_XOR_MULT_DOSStub_66f3 {
  strings:
    $key_66f3 = { 32 9b [2] 46 83 [2] 01 81 [2] 46 90 [2] 08 9c [2] 04 96 [2] 13 9d [2] 08 d3 [2] 35 }

  condition:
    any of them
}