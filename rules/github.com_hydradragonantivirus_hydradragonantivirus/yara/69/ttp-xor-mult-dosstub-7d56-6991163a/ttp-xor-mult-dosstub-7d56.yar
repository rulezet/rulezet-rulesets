rule TTP_XOR_MULT_DOSStub_7d56 {
  strings:
    $key_7d56 = { 29 3e [2] 5d 26 [2] 1a 24 [2] 5d 35 [2] 13 39 [2] 1f 33 [2] 08 38 [2] 13 76 [2] 2e }

  condition:
    any of them
}