rule TTP_XOR_MULT_DOSStub_3461 {
  strings:
    $key_3461 = { 60 09 [2] 14 11 [2] 53 13 [2] 14 02 [2] 5a 0e [2] 56 04 [2] 41 0f [2] 5a 41 [2] 67 }

  condition:
    any of them
}