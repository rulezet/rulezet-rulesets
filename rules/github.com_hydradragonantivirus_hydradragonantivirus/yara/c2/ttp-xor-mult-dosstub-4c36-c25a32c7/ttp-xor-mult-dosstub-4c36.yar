rule TTP_XOR_MULT_DOSStub_4c36 {
  strings:
    $key_4c36 = { 18 5e [2] 6c 46 [2] 2b 44 [2] 6c 55 [2] 22 59 [2] 2e 53 [2] 39 58 [2] 22 16 [2] 1f }

  condition:
    any of them
}