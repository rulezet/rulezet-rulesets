rule TTP_XOR_MULT_DOSStub_135f {
  strings:
    $key_135f = { 47 37 [2] 33 2f [2] 74 2d [2] 33 3c [2] 7d 30 [2] 71 3a [2] 66 31 [2] 7d 7f [2] 40 }

  condition:
    any of them
}