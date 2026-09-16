rule TTP_XOR_MULT_DOSStub_311f {
  strings:
    $key_311f = { 65 77 [2] 11 6f [2] 56 6d [2] 11 7c [2] 5f 70 [2] 53 7a [2] 44 71 [2] 5f 3f [2] 62 }

  condition:
    any of them
}