rule TTP_XOR_MULT_DOSStub_7912 {
  strings:
    $key_7912 = { 2d 7a [2] 59 62 [2] 1e 60 [2] 59 71 [2] 17 7d [2] 1b 77 [2] 0c 7c [2] 17 32 [2] 2a }

  condition:
    any of them
}