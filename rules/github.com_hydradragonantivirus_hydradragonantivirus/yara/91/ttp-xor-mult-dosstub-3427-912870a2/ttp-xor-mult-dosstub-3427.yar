rule TTP_XOR_MULT_DOSStub_3427 {
  strings:
    $key_3427 = { 60 4f [2] 14 57 [2] 53 55 [2] 14 44 [2] 5a 48 [2] 56 42 [2] 41 49 [2] 5a 07 [2] 67 }

  condition:
    any of them
}