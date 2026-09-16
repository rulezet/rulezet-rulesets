rule TTP_XOR_MULT_DOSStub_345f {
  strings:
    $key_345f = { 60 37 [2] 14 2f [2] 53 2d [2] 14 3c [2] 5a 30 [2] 56 3a [2] 41 31 [2] 5a 7f [2] 67 }

  condition:
    any of them
}