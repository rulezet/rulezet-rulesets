rule TTP_XOR_MULT_DOSStub_791a {
  strings:
    $key_791a = { 2d 72 [2] 59 6a [2] 1e 68 [2] 59 79 [2] 17 75 [2] 1b 7f [2] 0c 74 [2] 17 3a [2] 2a }

  condition:
    any of them
}