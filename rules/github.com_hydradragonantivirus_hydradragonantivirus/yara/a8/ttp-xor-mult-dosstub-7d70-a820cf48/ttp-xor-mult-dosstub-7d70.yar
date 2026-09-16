rule TTP_XOR_MULT_DOSStub_7d70 {
  strings:
    $key_7d70 = { 29 18 [2] 5d 00 [2] 1a 02 [2] 5d 13 [2] 13 1f [2] 1f 15 [2] 08 1e [2] 13 50 [2] 2e }

  condition:
    any of them
}