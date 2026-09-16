rule TTP_XOR_MULT_DOSStub_3161 {
  strings:
    $key_3161 = { 65 09 [2] 11 11 [2] 56 13 [2] 11 02 [2] 5f 0e [2] 53 04 [2] 44 0f [2] 5f 41 [2] 62 }

  condition:
    any of them
}