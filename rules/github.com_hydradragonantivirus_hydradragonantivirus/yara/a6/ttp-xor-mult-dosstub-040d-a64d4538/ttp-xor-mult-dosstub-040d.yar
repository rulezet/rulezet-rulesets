rule TTP_XOR_MULT_DOSStub_040d {
  strings:
    $key_040d = { 50 65 [2] 24 7d [2] 63 7f [2] 24 6e [2] 6a 62 [2] 66 68 [2] 71 63 [2] 6a 2d [2] 57 }

  condition:
    any of them
}