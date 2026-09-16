rule TTP_XOR_MULT_DOSStub_6c71 {
  strings:
    $key_6c71 = { 38 19 [2] 4c 01 [2] 0b 03 [2] 4c 12 [2] 02 1e [2] 0e 14 [2] 19 1f [2] 02 51 [2] 3f }

  condition:
    any of them
}