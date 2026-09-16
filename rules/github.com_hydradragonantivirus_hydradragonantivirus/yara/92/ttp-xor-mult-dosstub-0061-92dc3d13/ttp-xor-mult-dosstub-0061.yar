rule TTP_XOR_MULT_DOSStub_0061 {
  strings:
    $key_0061 = { 54 09 [2] 20 11 [2] 67 13 [2] 20 02 [2] 6e 0e [2] 62 04 [2] 75 0f [2] 6e 41 [2] 53 }

  condition:
    any of them
}