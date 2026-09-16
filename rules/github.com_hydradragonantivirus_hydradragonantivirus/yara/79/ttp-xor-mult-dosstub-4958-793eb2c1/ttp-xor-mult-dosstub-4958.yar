rule TTP_XOR_MULT_DOSStub_4958 {
  strings:
    $key_4958 = { 1d 30 [2] 69 28 [2] 2e 2a [2] 69 3b [2] 27 37 [2] 2b 3d [2] 3c 36 [2] 27 78 [2] 1a }

  condition:
    any of them
}