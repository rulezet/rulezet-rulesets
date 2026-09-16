rule TTP_XOR_MULT_DOSStub_6861 {
  strings:
    $key_6861 = { 3c 09 [2] 48 11 [2] 0f 13 [2] 48 02 [2] 06 0e [2] 0a 04 [2] 1d 0f [2] 06 41 [2] 3b }

  condition:
    any of them
}