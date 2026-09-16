rule TTP_XOR_MULT_DOSStub_777f {
  strings:
    $key_777f = { 23 17 [2] 57 0f [2] 10 0d [2] 57 1c [2] 19 10 [2] 15 1a [2] 02 11 [2] 19 5f [2] 24 }

  condition:
    any of them
}