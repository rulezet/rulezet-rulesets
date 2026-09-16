rule TTP_XOR_MULT_DOSStub_741f {
  strings:
    $key_741f = { 20 77 [2] 54 6f [2] 13 6d [2] 54 7c [2] 1a 70 [2] 16 7a [2] 01 71 [2] 1a 3f [2] 27 }

  condition:
    any of them
}