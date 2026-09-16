rule TTP_XOR_MULT_DOSStub_5625 {
  strings:
    $key_5625 = { 02 4d [2] 76 55 [2] 31 57 [2] 76 46 [2] 38 4a [2] 34 40 [2] 23 4b [2] 38 05 [2] 05 }

  condition:
    any of them
}