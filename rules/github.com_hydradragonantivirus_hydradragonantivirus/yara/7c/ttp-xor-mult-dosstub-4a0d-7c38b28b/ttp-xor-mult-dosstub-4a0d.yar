rule TTP_XOR_MULT_DOSStub_4a0d {
  strings:
    $key_4a0d = { 1e 65 [2] 6a 7d [2] 2d 7f [2] 6a 6e [2] 24 62 [2] 28 68 [2] 3f 63 [2] 24 2d [2] 19 }

  condition:
    any of them
}