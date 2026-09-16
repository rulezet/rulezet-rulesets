rule TTP_XOR_MULT_DOSStub_6400 {
  strings:
    $key_6400 = { 30 68 [2] 44 70 [2] 03 72 [2] 44 63 [2] 0a 6f [2] 06 65 [2] 11 6e [2] 0a 20 [2] 37 }

  condition:
    any of them
}