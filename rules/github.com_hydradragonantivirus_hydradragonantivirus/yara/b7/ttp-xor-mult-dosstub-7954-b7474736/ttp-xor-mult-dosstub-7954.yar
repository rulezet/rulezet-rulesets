rule TTP_XOR_MULT_DOSStub_7954 {
  strings:
    $key_7954 = { 2d 3c [2] 59 24 [2] 1e 26 [2] 59 37 [2] 17 3b [2] 1b 31 [2] 0c 3a [2] 17 74 [2] 2a }

  condition:
    any of them
}