rule TTP_XOR_MULT_DOSStub_7826 {
  strings:
    $key_7826 = { 2c 4e [2] 58 56 [2] 1f 54 [2] 58 45 [2] 16 49 [2] 1a 43 [2] 0d 48 [2] 16 06 [2] 2b }

  condition:
    any of them
}