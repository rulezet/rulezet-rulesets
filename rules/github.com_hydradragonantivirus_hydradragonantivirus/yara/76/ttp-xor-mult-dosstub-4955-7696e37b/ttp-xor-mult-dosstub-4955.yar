rule TTP_XOR_MULT_DOSStub_4955 {
  strings:
    $key_4955 = { 1d 3d [2] 69 25 [2] 2e 27 [2] 69 36 [2] 27 3a [2] 2b 30 [2] 3c 3b [2] 27 75 [2] 1a }

  condition:
    any of them
}