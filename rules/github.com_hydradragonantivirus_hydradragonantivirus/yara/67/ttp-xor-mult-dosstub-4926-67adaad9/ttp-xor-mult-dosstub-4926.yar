rule TTP_XOR_MULT_DOSStub_4926 {
  strings:
    $key_4926 = { 1d 4e [2] 69 56 [2] 2e 54 [2] 69 45 [2] 27 49 [2] 2b 43 [2] 3c 48 [2] 27 06 [2] 1a }

  condition:
    any of them
}