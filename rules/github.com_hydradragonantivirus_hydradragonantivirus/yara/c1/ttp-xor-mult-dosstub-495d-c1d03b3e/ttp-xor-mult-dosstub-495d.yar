rule TTP_XOR_MULT_DOSStub_495d {
  strings:
    $key_495d = { 1d 35 [2] 69 2d [2] 2e 2f [2] 69 3e [2] 27 32 [2] 2b 38 [2] 3c 33 [2] 27 7d [2] 1a }

  condition:
    any of them
}