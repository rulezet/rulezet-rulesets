rule TTP_XOR_MULT_DOSStub_7959 {
  strings:
    $key_7959 = { 2d 31 [2] 59 29 [2] 1e 2b [2] 59 3a [2] 17 36 [2] 1b 3c [2] 0c 37 [2] 17 79 [2] 2a }

  condition:
    any of them
}