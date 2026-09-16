rule TTP_XOR_MULT_DOSStub_045f {
  strings:
    $key_045f = { 50 37 [2] 24 2f [2] 63 2d [2] 24 3c [2] 6a 30 [2] 66 3a [2] 71 31 [2] 6a 7f [2] 57 }

  condition:
    any of them
}