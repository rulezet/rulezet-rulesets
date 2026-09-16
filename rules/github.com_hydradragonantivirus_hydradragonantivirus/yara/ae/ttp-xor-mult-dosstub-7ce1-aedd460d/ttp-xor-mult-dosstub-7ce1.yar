rule TTP_XOR_MULT_DOSStub_7ce1 {
  strings:
    $key_7ce1 = { 28 89 [2] 5c 91 [2] 1b 93 [2] 5c 82 [2] 12 8e [2] 1e 84 [2] 09 8f [2] 12 c1 [2] 2f }

  condition:
    any of them
}