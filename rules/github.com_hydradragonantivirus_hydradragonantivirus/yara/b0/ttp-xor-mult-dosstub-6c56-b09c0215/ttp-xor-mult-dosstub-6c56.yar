rule TTP_XOR_MULT_DOSStub_6c56 {
  strings:
    $key_6c56 = { 38 3e [2] 4c 26 [2] 0b 24 [2] 4c 35 [2] 02 39 [2] 0e 33 [2] 19 38 [2] 02 76 [2] 3f }

  condition:
    any of them
}