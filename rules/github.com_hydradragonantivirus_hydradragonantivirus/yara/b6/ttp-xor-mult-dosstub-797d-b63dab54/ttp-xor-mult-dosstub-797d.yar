rule TTP_XOR_MULT_DOSStub_797d {
  strings:
    $key_797d = { 2d 15 [2] 59 0d [2] 1e 0f [2] 59 1e [2] 17 12 [2] 1b 18 [2] 0c 13 [2] 17 5d [2] 2a }

  condition:
    any of them
}