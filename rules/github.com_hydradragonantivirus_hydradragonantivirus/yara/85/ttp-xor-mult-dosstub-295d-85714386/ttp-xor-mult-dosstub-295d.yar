rule TTP_XOR_MULT_DOSStub_295d {
  strings:
    $key_295d = { 7d 35 [2] 09 2d [2] 4e 2f [2] 09 3e [2] 47 32 [2] 4b 38 [2] 5c 33 [2] 47 7d [2] 7a }

  condition:
    any of them
}