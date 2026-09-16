rule TTP_XOR_MULT_DOSStub_7c31 {
  strings:
    $key_7c31 = { 28 59 [2] 5c 41 [2] 1b 43 [2] 5c 52 [2] 12 5e [2] 1e 54 [2] 09 5f [2] 12 11 [2] 2f }

  condition:
    any of them
}