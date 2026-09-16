rule TTP_XOR_MULT_DOSStub_49eb {
  strings:
    $key_49eb = { 1d 83 [2] 69 9b [2] 2e 99 [2] 69 88 [2] 27 84 [2] 2b 8e [2] 3c 85 [2] 27 cb [2] 1a }

  condition:
    any of them
}