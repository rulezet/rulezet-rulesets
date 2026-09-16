rule TTP_XOR_MULT_DOSStub_6c17 {
  strings:
    $key_6c17 = { 38 7f [2] 4c 67 [2] 0b 65 [2] 4c 74 [2] 02 78 [2] 0e 72 [2] 19 79 [2] 02 37 [2] 3f }

  condition:
    any of them
}