rule TTP_XOR_MULT_DOSStub_390d {
  strings:
    $key_390d = { 6d 65 [2] 19 7d [2] 5e 7f [2] 19 6e [2] 57 62 [2] 5b 68 [2] 4c 63 [2] 57 2d [2] 6a }

  condition:
    any of them
}