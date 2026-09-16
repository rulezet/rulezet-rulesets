rule TTP_XOR_MULT_DOSStub_40e7 {
  strings:
    $key_40e7 = { 14 8f [2] 60 97 [2] 27 95 [2] 60 84 [2] 2e 88 [2] 22 82 [2] 35 89 [2] 2e c7 [2] 13 }

  condition:
    any of them
}