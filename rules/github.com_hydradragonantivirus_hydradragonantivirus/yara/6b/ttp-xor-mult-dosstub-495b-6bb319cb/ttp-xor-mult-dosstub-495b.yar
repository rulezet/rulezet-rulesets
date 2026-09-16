rule TTP_XOR_MULT_DOSStub_495b {
  strings:
    $key_495b = { 1d 33 [2] 69 2b [2] 2e 29 [2] 69 38 [2] 27 34 [2] 2b 3e [2] 3c 35 [2] 27 7b [2] 1a }

  condition:
    any of them
}