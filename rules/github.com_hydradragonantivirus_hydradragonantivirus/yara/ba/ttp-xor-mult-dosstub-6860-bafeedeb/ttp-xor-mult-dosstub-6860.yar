rule TTP_XOR_MULT_DOSStub_6860 {
  strings:
    $key_6860 = { 3c 08 [2] 48 10 [2] 0f 12 [2] 48 03 [2] 06 0f [2] 0a 05 [2] 1d 0e [2] 06 40 [2] 3b }

  condition:
    any of them
}