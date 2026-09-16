rule TTP_XOR_MULT_DOSStub_011f {
  strings:
    $key_011f = { 55 77 [2] 21 6f [2] 66 6d [2] 21 7c [2] 6f 70 [2] 63 7a [2] 74 71 [2] 6f 3f [2] 52 }

  condition:
    any of them
}