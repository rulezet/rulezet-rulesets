rule TTP_XOR_MULT_DOSStub_514a {
  strings:
    $key_514a = { 05 22 [2] 71 3a [2] 36 38 [2] 71 29 [2] 3f 25 [2] 33 2f [2] 24 24 [2] 3f 6a [2] 02 }

  condition:
    any of them
}