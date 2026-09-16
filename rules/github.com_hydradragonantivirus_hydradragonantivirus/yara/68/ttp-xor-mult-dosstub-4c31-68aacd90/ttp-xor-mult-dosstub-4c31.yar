rule TTP_XOR_MULT_DOSStub_4c31 {
  strings:
    $key_4c31 = { 18 59 [2] 6c 41 [2] 2b 43 [2] 6c 52 [2] 22 5e [2] 2e 54 [2] 39 5f [2] 22 11 [2] 1f }

  condition:
    any of them
}