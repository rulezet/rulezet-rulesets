rule TTP_XOR_MULT_DOSStub_7c36 {
  strings:
    $key_7c36 = { 28 5e [2] 5c 46 [2] 1b 44 [2] 5c 55 [2] 12 59 [2] 1e 53 [2] 09 58 [2] 12 16 [2] 2f }

  condition:
    any of them
}