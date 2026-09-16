rule TTP_XOR_MULT_DOSStub_6c40 {
  strings:
    $key_6c40 = { 38 28 [2] 4c 30 [2] 0b 32 [2] 4c 23 [2] 02 2f [2] 0e 25 [2] 19 2e [2] 02 60 [2] 3f }

  condition:
    any of them
}