rule TTP_XOR_MULT_DOSStub_4c50 {
  strings:
    $key_4c50 = { 18 38 [2] 6c 20 [2] 2b 22 [2] 6c 33 [2] 22 3f [2] 2e 35 [2] 39 3e [2] 22 70 [2] 1f }

  condition:
    any of them
}