rule TTP_XOR_MULT_DOSStub_7cf0 {
  strings:
    $key_7cf0 = { 28 98 [2] 5c 80 [2] 1b 82 [2] 5c 93 [2] 12 9f [2] 1e 95 [2] 09 9e [2] 12 d0 [2] 2f }

  condition:
    any of them
}