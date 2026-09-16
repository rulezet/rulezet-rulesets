rule TTP_XOR_MULT_DOSStub_4227 {
  strings:
    $key_4227 = { 16 4f [2] 62 57 [2] 25 55 [2] 62 44 [2] 2c 48 [2] 20 42 [2] 37 49 [2] 2c 07 [2] 11 }

  condition:
    any of them
}