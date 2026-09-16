rule TTP_XOR_MULT_DOSStub_5223 {
  strings:
    $key_5223 = { 06 4b [2] 72 53 [2] 35 51 [2] 72 40 [2] 3c 4c [2] 30 46 [2] 27 4d [2] 3c 03 [2] 01 }

  condition:
    any of them
}