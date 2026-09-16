rule TTP_XOR_MULT_DOSStub_1a20 {
  strings:
    $key_1a20 = { 4e 48 [2] 3a 50 [2] 7d 52 [2] 3a 43 [2] 74 4f [2] 78 45 [2] 6f 4e [2] 74 00 [2] 49 }

  condition:
    any of them
}