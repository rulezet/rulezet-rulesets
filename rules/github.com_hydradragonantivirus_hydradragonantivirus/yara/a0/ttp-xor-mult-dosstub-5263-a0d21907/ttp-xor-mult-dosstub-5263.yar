rule TTP_XOR_MULT_DOSStub_5263 {
  strings:
    $key_5263 = { 06 0b [2] 72 13 [2] 35 11 [2] 72 00 [2] 3c 0c [2] 30 06 [2] 27 0d [2] 3c 43 [2] 01 }

  condition:
    any of them
}