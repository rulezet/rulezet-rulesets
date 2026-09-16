rule TTP_XOR_MULT_DOSStub_6612 {
  strings:
    $key_6612 = { 32 7a [2] 46 62 [2] 01 60 [2] 46 71 [2] 08 7d [2] 04 77 [2] 13 7c [2] 08 32 [2] 35 }

  condition:
    any of them
}