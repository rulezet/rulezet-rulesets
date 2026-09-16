rule TTP_XOR_MULT_DOSStub_1023 {
  strings:
    $key_1023 = { 44 4b [2] 30 53 [2] 77 51 [2] 30 40 [2] 7e 4c [2] 72 46 [2] 65 4d [2] 7e 03 [2] 43 }

  condition:
    any of them
}