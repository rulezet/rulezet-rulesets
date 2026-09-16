rule TTP_XOR_MULT_DOSStub_3a61 {
  strings:
    $key_3a61 = { 6e 09 [2] 1a 11 [2] 5d 13 [2] 1a 02 [2] 54 0e [2] 58 04 [2] 4f 0f [2] 54 41 [2] 69 }

  condition:
    any of them
}