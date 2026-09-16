rule TTP_XOR_MULT_DOSStub_0761 {
  strings:
    $key_0761 = { 53 09 [2] 27 11 [2] 60 13 [2] 27 02 [2] 69 0e [2] 65 04 [2] 72 0f [2] 69 41 [2] 54 }

  condition:
    any of them
}