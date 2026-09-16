rule TTP_XOR_MULT_DOSStub_7f61 {
  strings:
    $key_7f61 = { 2b 09 [2] 5f 11 [2] 18 13 [2] 5f 02 [2] 11 0e [2] 1d 04 [2] 0a 0f [2] 11 41 [2] 2c }

  condition:
    any of them
}