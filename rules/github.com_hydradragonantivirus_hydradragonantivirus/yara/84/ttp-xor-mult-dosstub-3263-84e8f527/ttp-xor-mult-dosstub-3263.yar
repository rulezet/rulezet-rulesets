rule TTP_XOR_MULT_DOSStub_3263 {
  strings:
    $key_3263 = { 66 0b [2] 12 13 [2] 55 11 [2] 12 00 [2] 5c 0c [2] 50 06 [2] 47 0d [2] 5c 43 [2] 61 }

  condition:
    any of them
}