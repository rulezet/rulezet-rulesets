rule TTP_XOR_MULT_DOSStub_49ec {
  strings:
    $key_49ec = { 1d 84 [2] 69 9c [2] 2e 9e [2] 69 8f [2] 27 83 [2] 2b 89 [2] 3c 82 [2] 27 cc [2] 1a }

  condition:
    any of them
}