rule TTP_XOR_MULT_DOSStub_4773 {
  strings:
    $key_4773 = { 13 1b [2] 67 03 [2] 20 01 [2] 67 10 [2] 29 1c [2] 25 16 [2] 32 1d [2] 29 53 [2] 14 }

  condition:
    any of them
}