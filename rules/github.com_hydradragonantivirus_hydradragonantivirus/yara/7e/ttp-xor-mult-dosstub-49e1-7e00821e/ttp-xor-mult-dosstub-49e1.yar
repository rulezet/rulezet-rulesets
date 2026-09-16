rule TTP_XOR_MULT_DOSStub_49e1 {
  strings:
    $key_49e1 = { 1d 89 [2] 69 91 [2] 2e 93 [2] 69 82 [2] 27 8e [2] 2b 84 [2] 3c 8f [2] 27 c1 [2] 1a }

  condition:
    any of them
}