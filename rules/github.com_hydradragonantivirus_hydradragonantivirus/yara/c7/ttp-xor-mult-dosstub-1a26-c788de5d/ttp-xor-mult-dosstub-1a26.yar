rule TTP_XOR_MULT_DOSStub_1a26 {
  strings:
    $key_1a26 = { 4e 4e [2] 3a 56 [2] 7d 54 [2] 3a 45 [2] 74 49 [2] 78 43 [2] 6f 48 [2] 74 06 [2] 49 }

  condition:
    any of them
}