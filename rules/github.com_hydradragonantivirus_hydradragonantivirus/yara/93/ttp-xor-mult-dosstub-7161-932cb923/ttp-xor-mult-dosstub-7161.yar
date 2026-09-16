rule TTP_XOR_MULT_DOSStub_7161 {
  strings:
    $key_7161 = { 25 09 [2] 51 11 [2] 16 13 [2] 51 02 [2] 1f 0e [2] 13 04 [2] 04 0f [2] 1f 41 [2] 22 }

  condition:
    any of them
}