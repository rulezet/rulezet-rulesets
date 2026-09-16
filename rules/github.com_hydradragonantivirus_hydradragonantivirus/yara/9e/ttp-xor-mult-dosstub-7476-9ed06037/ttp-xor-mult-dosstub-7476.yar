rule TTP_XOR_MULT_DOSStub_7476 {
  strings:
    $key_7476 = { 20 1e [2] 54 06 [2] 13 04 [2] 54 15 [2] 1a 19 [2] 16 13 [2] 01 18 [2] 1a 56 [2] 27 }

  condition:
    any of them
}