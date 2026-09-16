rule TTP_XOR_MULT_DOSStub_4b76 {
  strings:
    $key_4b76 = { 1f 1e [2] 6b 06 [2] 2c 04 [2] 6b 15 [2] 25 19 [2] 29 13 [2] 3e 18 [2] 25 56 [2] 18 }

  condition:
    any of them
}