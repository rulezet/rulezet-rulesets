rule TTP_XOR_MULT_DOSStub_600a {
  strings:
    $key_600a = { 34 62 [2] 40 7a [2] 07 78 [2] 40 69 [2] 0e 65 [2] 02 6f [2] 15 64 [2] 0e 2a [2] 33 }

  condition:
    any of them
}