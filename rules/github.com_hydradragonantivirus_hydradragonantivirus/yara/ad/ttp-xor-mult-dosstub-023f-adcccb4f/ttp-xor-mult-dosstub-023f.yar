rule TTP_XOR_MULT_DOSStub_023f {
  strings:
    $key_023f = { 56 57 [2] 22 4f [2] 65 4d [2] 22 5c [2] 6c 50 [2] 60 5a [2] 77 51 [2] 6c 1f [2] 51 }

  condition:
    any of them
}