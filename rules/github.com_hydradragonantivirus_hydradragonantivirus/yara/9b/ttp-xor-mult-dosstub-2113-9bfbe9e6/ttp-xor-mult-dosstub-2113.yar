rule TTP_XOR_MULT_DOSStub_2113 {
  strings:
    $key_2113 = { 75 7b [2] 01 63 [2] 46 61 [2] 01 70 [2] 4f 7c [2] 43 76 [2] 54 7d [2] 4f 33 [2] 72 }

  condition:
    any of them
}