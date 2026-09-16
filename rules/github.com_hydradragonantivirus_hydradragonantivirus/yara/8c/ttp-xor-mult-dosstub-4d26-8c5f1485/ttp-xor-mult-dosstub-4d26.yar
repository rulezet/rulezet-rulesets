rule TTP_XOR_MULT_DOSStub_4d26 {
  strings:
    $key_4d26 = { 19 4e [2] 6d 56 [2] 2a 54 [2] 6d 45 [2] 23 49 [2] 2f 43 [2] 38 48 [2] 23 06 [2] 1e }

  condition:
    any of them
}