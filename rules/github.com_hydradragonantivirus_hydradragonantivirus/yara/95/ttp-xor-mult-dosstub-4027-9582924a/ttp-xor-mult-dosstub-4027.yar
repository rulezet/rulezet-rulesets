rule TTP_XOR_MULT_DOSStub_4027 {
  strings:
    $key_4027 = { 14 4f [2] 60 57 [2] 27 55 [2] 60 44 [2] 2e 48 [2] 22 42 [2] 35 49 [2] 2e 07 [2] 13 }

  condition:
    any of them
}