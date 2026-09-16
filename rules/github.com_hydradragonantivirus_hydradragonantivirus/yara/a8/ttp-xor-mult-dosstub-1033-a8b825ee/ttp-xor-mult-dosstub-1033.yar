rule TTP_XOR_MULT_DOSStub_1033 {
  strings:
    $key_1033 = { 44 5b [2] 30 43 [2] 77 41 [2] 30 50 [2] 7e 5c [2] 72 56 [2] 65 5d [2] 7e 13 [2] 43 }

  condition:
    any of them
}