rule TTP_XOR_MULT_DOSStub_4976 {
  strings:
    $key_4976 = { 1d 1e [2] 69 06 [2] 2e 04 [2] 69 15 [2] 27 19 [2] 2b 13 [2] 3c 18 [2] 27 56 [2] 1a }

  condition:
    any of them
}