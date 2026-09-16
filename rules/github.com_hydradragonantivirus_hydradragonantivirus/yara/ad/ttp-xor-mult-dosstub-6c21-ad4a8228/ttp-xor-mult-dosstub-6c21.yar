rule TTP_XOR_MULT_DOSStub_6c21 {
  strings:
    $key_6c21 = { 38 49 [2] 4c 51 [2] 0b 53 [2] 4c 42 [2] 02 4e [2] 0e 44 [2] 19 4f [2] 02 01 [2] 3f }

  condition:
    any of them
}