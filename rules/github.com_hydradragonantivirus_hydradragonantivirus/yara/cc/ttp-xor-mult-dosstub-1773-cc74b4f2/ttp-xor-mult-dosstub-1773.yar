rule TTP_XOR_MULT_DOSStub_1773 {
  strings:
    $key_1773 = { 43 1b [2] 37 03 [2] 70 01 [2] 37 10 [2] 79 1c [2] 75 16 [2] 62 1d [2] 79 53 [2] 44 }

  condition:
    any of them
}