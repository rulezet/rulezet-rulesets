rule TTP_XOR_MULT_DOSStub_2ee1 {
  strings:
    $key_2ee1 = { 7a 89 [2] 0e 91 [2] 49 93 [2] 0e 82 [2] 40 8e [2] 4c 84 [2] 5b 8f [2] 40 c1 [2] 7d }

  condition:
    any of them
}