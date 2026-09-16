rule TTP_XOR_MULT_DOSStub_395d {
  strings:
    $key_395d = { 6d 35 [2] 19 2d [2] 5e 2f [2] 19 3e [2] 57 32 [2] 5b 38 [2] 4c 33 [2] 57 7d [2] 6a }

  condition:
    any of them
}