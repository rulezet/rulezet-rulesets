rule TTP_XOR_MULT_DOSStub_497e {
  strings:
    $key_497e = { 1d 16 [2] 69 0e [2] 2e 0c [2] 69 1d [2] 27 11 [2] 2b 1b [2] 3c 10 [2] 27 5e [2] 1a }

  condition:
    any of them
}