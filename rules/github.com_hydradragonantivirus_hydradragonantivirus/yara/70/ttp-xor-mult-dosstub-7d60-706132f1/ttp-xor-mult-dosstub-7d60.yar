rule TTP_XOR_MULT_DOSStub_7d60 {
  strings:
    $key_7d60 = { 29 08 [2] 5d 10 [2] 1a 12 [2] 5d 03 [2] 13 0f [2] 1f 05 [2] 08 0e [2] 13 40 [2] 2e }

  condition:
    any of them
}