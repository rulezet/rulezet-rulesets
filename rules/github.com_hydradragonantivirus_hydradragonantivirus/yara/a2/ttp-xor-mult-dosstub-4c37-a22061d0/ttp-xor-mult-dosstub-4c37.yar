rule TTP_XOR_MULT_DOSStub_4c37 {
  strings:
    $key_4c37 = { 18 5f [2] 6c 47 [2] 2b 45 [2] 6c 54 [2] 22 58 [2] 2e 52 [2] 39 59 [2] 22 17 [2] 1f }

  condition:
    any of them
}