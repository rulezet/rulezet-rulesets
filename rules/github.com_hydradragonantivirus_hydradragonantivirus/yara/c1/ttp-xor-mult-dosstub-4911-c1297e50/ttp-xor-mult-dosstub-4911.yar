rule TTP_XOR_MULT_DOSStub_4911 {
  strings:
    $key_4911 = { 1d 79 [2] 69 61 [2] 2e 63 [2] 69 72 [2] 27 7e [2] 2b 74 [2] 3c 7f [2] 27 31 [2] 1a }

  condition:
    any of them
}