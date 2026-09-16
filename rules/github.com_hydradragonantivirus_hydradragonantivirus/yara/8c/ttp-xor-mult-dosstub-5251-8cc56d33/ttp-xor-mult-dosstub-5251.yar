rule TTP_XOR_MULT_DOSStub_5251 {
  strings:
    $key_5251 = { 06 39 [2] 72 21 [2] 35 23 [2] 72 32 [2] 3c 3e [2] 30 34 [2] 27 3f [2] 3c 71 [2] 01 }

  condition:
    any of them
}