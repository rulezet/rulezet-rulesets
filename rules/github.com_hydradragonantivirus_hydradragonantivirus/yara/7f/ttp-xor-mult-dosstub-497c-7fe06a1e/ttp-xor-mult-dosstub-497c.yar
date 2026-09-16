rule TTP_XOR_MULT_DOSStub_497c {
  strings:
    $key_497c = { 1d 14 [2] 69 0c [2] 2e 0e [2] 69 1f [2] 27 13 [2] 2b 19 [2] 3c 12 [2] 27 5c [2] 1a }

  condition:
    any of them
}