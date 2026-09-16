rule TTP_XOR_MULT_DOSStub_497b {
  strings:
    $key_497b = { 1d 13 [2] 69 0b [2] 2e 09 [2] 69 18 [2] 27 14 [2] 2b 1e [2] 3c 15 [2] 27 5b [2] 1a }

  condition:
    any of them
}