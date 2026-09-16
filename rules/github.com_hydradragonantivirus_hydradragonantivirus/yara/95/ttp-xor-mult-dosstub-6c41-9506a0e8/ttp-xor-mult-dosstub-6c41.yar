rule TTP_XOR_MULT_DOSStub_6c41 {
  strings:
    $key_6c41 = { 38 29 [2] 4c 31 [2] 0b 33 [2] 4c 22 [2] 02 2e [2] 0e 24 [2] 19 2f [2] 02 61 [2] 3f }

  condition:
    any of them
}