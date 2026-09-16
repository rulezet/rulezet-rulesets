rule TTP_XOR_MULT_DOSStub_261f {
  strings:
    $key_261f = { 72 77 [2] 06 6f [2] 41 6d [2] 06 7c [2] 48 70 [2] 44 7a [2] 53 71 [2] 48 3f [2] 75 }

  condition:
    any of them
}