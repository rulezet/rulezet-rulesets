rule TTP_XOR_MULT_DOSStub_1022 {
  strings:
    $key_1022 = { 44 4a [2] 30 52 [2] 77 50 [2] 30 41 [2] 7e 4d [2] 72 47 [2] 65 4c [2] 7e 02 [2] 43 }

  condition:
    any of them
}