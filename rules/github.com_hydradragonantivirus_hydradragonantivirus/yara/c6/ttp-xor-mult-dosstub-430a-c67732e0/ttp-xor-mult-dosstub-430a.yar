rule TTP_XOR_MULT_DOSStub_430a {
  strings:
    $key_430a = { 17 62 [2] 63 7a [2] 24 78 [2] 63 69 [2] 2d 65 [2] 21 6f [2] 36 64 [2] 2d 2a [2] 10 }

  condition:
    any of them
}