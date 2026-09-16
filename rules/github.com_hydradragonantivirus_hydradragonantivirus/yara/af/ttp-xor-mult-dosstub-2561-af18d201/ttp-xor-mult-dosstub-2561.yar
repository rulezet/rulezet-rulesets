rule TTP_XOR_MULT_DOSStub_2561 {
  strings:
    $key_2561 = { 71 09 [2] 05 11 [2] 42 13 [2] 05 02 [2] 4b 0e [2] 47 04 [2] 50 0f [2] 4b 41 [2] 76 }

  condition:
    any of them
}