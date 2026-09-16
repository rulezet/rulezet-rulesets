rule TTP_XOR_MULT_DOSStub_7426 {
  strings:
    $key_7426 = { 20 4e [2] 54 56 [2] 13 54 [2] 54 45 [2] 1a 49 [2] 16 43 [2] 01 48 [2] 1a 06 [2] 27 }

  condition:
    any of them
}