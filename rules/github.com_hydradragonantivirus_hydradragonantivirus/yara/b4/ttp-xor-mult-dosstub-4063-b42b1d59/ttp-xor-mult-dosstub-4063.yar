rule TTP_XOR_MULT_DOSStub_4063 {
  strings:
    $key_4063 = { 14 0b [2] 60 13 [2] 27 11 [2] 60 00 [2] 2e 0c [2] 22 06 [2] 35 0d [2] 2e 43 [2] 13 }

  condition:
    any of them
}