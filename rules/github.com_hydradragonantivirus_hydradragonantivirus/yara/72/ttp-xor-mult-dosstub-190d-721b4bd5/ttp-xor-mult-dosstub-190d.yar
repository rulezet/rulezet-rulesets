rule TTP_XOR_MULT_DOSStub_190d {
  strings:
    $key_190d = { 4d 65 [2] 39 7d [2] 7e 7f [2] 39 6e [2] 77 62 [2] 7b 68 [2] 6c 63 [2] 77 2d [2] 4a }

  condition:
    any of them
}