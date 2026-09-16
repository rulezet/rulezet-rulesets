rule TTP_XOR_MULT_DOSStub_043f {
  strings:
    $key_043f = { 50 57 [2] 24 4f [2] 63 4d [2] 24 5c [2] 6a 50 [2] 66 5a [2] 71 51 [2] 6a 1f [2] 57 }

  condition:
    any of them
}