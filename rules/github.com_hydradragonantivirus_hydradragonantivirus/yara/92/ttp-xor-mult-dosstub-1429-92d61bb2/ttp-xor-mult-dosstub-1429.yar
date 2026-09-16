rule TTP_XOR_MULT_DOSStub_1429 {
  strings:
    $key_1429 = { 40 41 [2] 34 59 [2] 73 5b [2] 34 4a [2] 7a 46 [2] 76 4c [2] 61 47 [2] 7a 09 [2] 47 }

  condition:
    any of them
}