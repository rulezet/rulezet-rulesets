rule TTP_XOR_MULT_DOSStub_2013 {
  strings:
    $key_2013 = { 74 7b [2] 00 63 [2] 47 61 [2] 00 70 [2] 4e 7c [2] 42 76 [2] 55 7d [2] 4e 33 [2] 73 }

  condition:
    any of them
}