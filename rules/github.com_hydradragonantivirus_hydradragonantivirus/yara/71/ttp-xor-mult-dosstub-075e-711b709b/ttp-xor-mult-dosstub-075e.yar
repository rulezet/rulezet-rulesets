rule TTP_XOR_MULT_DOSStub_075e {
  strings:
    $key_075e = { 53 36 [2] 27 2e [2] 60 2c [2] 27 3d [2] 69 31 [2] 65 3b [2] 72 30 [2] 69 7e [2] 54 }

  condition:
    any of them
}