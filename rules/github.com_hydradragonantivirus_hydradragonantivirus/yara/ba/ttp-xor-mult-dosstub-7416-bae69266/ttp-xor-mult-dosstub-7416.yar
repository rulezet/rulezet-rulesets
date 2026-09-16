rule TTP_XOR_MULT_DOSStub_7416 {
  strings:
    $key_7416 = { 20 7e [2] 54 66 [2] 13 64 [2] 54 75 [2] 1a 79 [2] 16 73 [2] 01 78 [2] 1a 36 [2] 27 }

  condition:
    any of them
}