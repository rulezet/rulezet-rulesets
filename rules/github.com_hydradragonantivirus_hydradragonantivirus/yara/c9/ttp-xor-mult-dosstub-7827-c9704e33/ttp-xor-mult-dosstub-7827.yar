rule TTP_XOR_MULT_DOSStub_7827 {
  strings:
    $key_7827 = { 2c 4f [2] 58 57 [2] 1f 55 [2] 58 44 [2] 16 48 [2] 1a 42 [2] 0d 49 [2] 16 07 [2] 2b }

  condition:
    any of them
}