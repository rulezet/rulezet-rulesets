rule TTP_XOR_MULT_DOSStub_521f {
  strings:
    $key_521f = { 06 77 [2] 72 6f [2] 35 6d [2] 72 7c [2] 3c 70 [2] 30 7a [2] 27 71 [2] 3c 3f [2] 01 }

  condition:
    any of them
}