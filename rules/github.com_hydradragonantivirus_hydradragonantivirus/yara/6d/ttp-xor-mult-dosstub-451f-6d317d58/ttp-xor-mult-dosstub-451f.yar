rule TTP_XOR_MULT_DOSStub_451f {
  strings:
    $key_451f = { 11 77 [2] 65 6f [2] 22 6d [2] 65 7c [2] 2b 70 [2] 27 7a [2] 30 71 [2] 2b 3f [2] 16 }

  condition:
    any of them
}