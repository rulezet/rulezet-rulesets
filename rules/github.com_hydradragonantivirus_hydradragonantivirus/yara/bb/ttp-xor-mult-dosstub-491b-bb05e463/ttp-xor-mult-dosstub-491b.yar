rule TTP_XOR_MULT_DOSStub_491b {
  strings:
    $key_491b = { 1d 73 [2] 69 6b [2] 2e 69 [2] 69 78 [2] 27 74 [2] 2b 7e [2] 3c 75 [2] 27 3b [2] 1a }

  condition:
    any of them
}