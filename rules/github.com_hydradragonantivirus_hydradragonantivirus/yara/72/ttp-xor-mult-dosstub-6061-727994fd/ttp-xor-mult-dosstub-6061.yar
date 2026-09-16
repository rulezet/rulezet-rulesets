rule TTP_XOR_MULT_DOSStub_6061 {
  strings:
    $key_6061 = { 34 09 [2] 40 11 [2] 07 13 [2] 40 02 [2] 0e 0e [2] 02 04 [2] 15 0f [2] 0e 41 [2] 33 }

  condition:
    any of them
}