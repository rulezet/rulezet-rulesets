rule TTP_XOR_MULT_DOSStub_6820 {
  strings:
    $key_6820 = { 3c 48 [2] 48 50 [2] 0f 52 [2] 48 43 [2] 06 4f [2] 0a 45 [2] 1d 4e [2] 06 00 [2] 3b }

  condition:
    any of them
}