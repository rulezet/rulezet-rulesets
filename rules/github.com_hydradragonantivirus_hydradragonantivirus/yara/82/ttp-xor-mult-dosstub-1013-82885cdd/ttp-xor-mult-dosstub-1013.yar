rule TTP_XOR_MULT_DOSStub_1013 {
  strings:
    $key_1013 = { 44 7b [2] 30 63 [2] 77 61 [2] 30 70 [2] 7e 7c [2] 72 76 [2] 65 7d [2] 7e 33 [2] 43 }

  condition:
    any of them
}