rule TTP_XOR_MULT_DOSStub_4721 {
  strings:
    $key_4721 = { 13 49 [2] 67 51 [2] 20 53 [2] 67 42 [2] 29 4e [2] 25 44 [2] 32 4f [2] 29 01 [2] 14 }

  condition:
    any of them
}