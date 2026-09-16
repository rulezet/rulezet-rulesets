rule TTP_XOR_MULT_DOSStub_7361 {
  strings:
    $key_7361 = { 27 09 [2] 53 11 [2] 14 13 [2] 53 02 [2] 1d 0e [2] 11 04 [2] 06 0f [2] 1d 41 [2] 20 }

  condition:
    any of them
}