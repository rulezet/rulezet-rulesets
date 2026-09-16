rule TTP_XOR_MULT_DOSStub_4c22 {
  strings:
    $key_4c22 = { 18 4a [2] 6c 52 [2] 2b 50 [2] 6c 41 [2] 22 4d [2] 2e 47 [2] 39 4c [2] 22 02 [2] 1f }

  condition:
    any of them
}