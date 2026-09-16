rule TTP_XOR_MULT_DOSStub_4427 {
  strings:
    $key_4427 = { 10 4f [2] 64 57 [2] 23 55 [2] 64 44 [2] 2a 48 [2] 26 42 [2] 31 49 [2] 2a 07 [2] 17 }

  condition:
    any of them
}