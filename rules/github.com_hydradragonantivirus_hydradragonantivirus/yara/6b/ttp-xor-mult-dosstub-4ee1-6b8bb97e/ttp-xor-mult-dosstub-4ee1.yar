rule TTP_XOR_MULT_DOSStub_4ee1 {
  strings:
    $key_4ee1 = { 1a 89 [2] 6e 91 [2] 29 93 [2] 6e 82 [2] 20 8e [2] 2c 84 [2] 3b 8f [2] 20 c1 [2] 1d }

  condition:
    any of them
}