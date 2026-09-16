rule TTP_XOR_MULT_DOSStub_7a26 {
  strings:
    $key_7a26 = { 2e 4e [2] 5a 56 [2] 1d 54 [2] 5a 45 [2] 14 49 [2] 18 43 [2] 0f 48 [2] 14 06 [2] 29 }

  condition:
    any of them
}