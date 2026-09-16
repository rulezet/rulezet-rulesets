rule TTP_XOR_MULT_DOSStub_4c41 {
  strings:
    $key_4c41 = { 18 29 [2] 6c 31 [2] 2b 33 [2] 6c 22 [2] 22 2e [2] 2e 24 [2] 39 2f [2] 22 61 [2] 1f }

  condition:
    any of them
}