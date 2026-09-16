rule TTP_XOR_MULT_DOSStub_1c27 {
  strings:
    $key_1c27 = { 48 4f [2] 3c 57 [2] 7b 55 [2] 3c 44 [2] 72 48 [2] 7e 42 [2] 69 49 [2] 72 07 [2] 4f }

  condition:
    any of them
}