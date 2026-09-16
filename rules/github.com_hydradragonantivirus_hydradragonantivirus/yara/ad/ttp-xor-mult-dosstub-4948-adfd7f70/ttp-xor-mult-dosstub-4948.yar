rule TTP_XOR_MULT_DOSStub_4948 {
  strings:
    $key_4948 = { 1d 20 [2] 69 38 [2] 2e 3a [2] 69 2b [2] 27 27 [2] 2b 2d [2] 3c 26 [2] 27 68 [2] 1a }

  condition:
    any of them
}