rule TTP_XOR_MULT_DOSStub_5d30 {
  strings:
    $key_5d30 = { 09 58 [2] 7d 40 [2] 3a 42 [2] 7d 53 [2] 33 5f [2] 3f 55 [2] 28 5e [2] 33 10 [2] 0e }

  condition:
    any of them
}