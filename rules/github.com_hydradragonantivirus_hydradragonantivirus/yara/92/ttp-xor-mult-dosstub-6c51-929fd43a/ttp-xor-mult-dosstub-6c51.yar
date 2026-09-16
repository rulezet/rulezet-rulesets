rule TTP_XOR_MULT_DOSStub_6c51 {
  strings:
    $key_6c51 = { 38 39 [2] 4c 21 [2] 0b 23 [2] 4c 32 [2] 02 3e [2] 0e 34 [2] 19 3f [2] 02 71 [2] 3f }

  condition:
    any of them
}