rule TTP_XOR_MULT_DOSStub_6c60 {
  strings:
    $key_6c60 = { 38 08 [2] 4c 10 [2] 0b 12 [2] 4c 03 [2] 02 0f [2] 0e 05 [2] 19 0e [2] 02 40 [2] 3f }

  condition:
    any of them
}