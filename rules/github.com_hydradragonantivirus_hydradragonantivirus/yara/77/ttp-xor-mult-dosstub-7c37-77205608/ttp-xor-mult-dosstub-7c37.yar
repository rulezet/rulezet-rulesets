rule TTP_XOR_MULT_DOSStub_7c37 {
  strings:
    $key_7c37 = { 28 5f [2] 5c 47 [2] 1b 45 [2] 5c 54 [2] 12 58 [2] 1e 52 [2] 09 59 [2] 12 17 [2] 2f }

  condition:
    any of them
}