rule TTP_XOR_MULT_DOSStub_7c50 {
  strings:
    $key_7c50 = { 28 38 [2] 5c 20 [2] 1b 22 [2] 5c 33 [2] 12 3f [2] 1e 35 [2] 09 3e [2] 12 70 [2] 2f }

  condition:
    any of them
}