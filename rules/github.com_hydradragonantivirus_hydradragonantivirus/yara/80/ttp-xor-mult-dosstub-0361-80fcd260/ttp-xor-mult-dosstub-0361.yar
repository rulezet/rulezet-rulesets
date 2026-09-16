rule TTP_XOR_MULT_DOSStub_0361 {
  strings:
    $key_0361 = { 57 09 [2] 23 11 [2] 64 13 [2] 23 02 [2] 6d 0e [2] 61 04 [2] 76 0f [2] 6d 41 [2] 50 }

  condition:
    any of them
}