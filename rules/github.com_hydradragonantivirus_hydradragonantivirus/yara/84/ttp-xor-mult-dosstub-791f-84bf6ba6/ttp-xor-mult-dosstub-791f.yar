rule TTP_XOR_MULT_DOSStub_791f {
  strings:
    $key_791f = { 2d 77 [2] 59 6f [2] 1e 6d [2] 59 7c [2] 17 70 [2] 1b 7a [2] 0c 71 [2] 17 3f [2] 2a }

  condition:
    any of them
}