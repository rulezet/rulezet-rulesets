rule TTP_XOR_MULT_DOSStub_3c16 {
  strings:
    $key_3c16 = { 68 7e [2] 1c 66 [2] 5b 64 [2] 1c 75 [2] 52 79 [2] 5e 73 [2] 49 78 [2] 52 36 [2] 6f }

  condition:
    any of them
}