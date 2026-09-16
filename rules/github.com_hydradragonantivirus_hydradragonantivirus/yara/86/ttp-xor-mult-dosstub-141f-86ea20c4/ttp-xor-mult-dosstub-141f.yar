rule TTP_XOR_MULT_DOSStub_141f {
  strings:
    $key_141f = { 40 77 [2] 34 6f [2] 73 6d [2] 34 7c [2] 7a 70 [2] 76 7a [2] 61 71 [2] 7a 3f [2] 47 }

  condition:
    any of them
}