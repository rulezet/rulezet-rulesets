rule TTP_XOR_MULT_DOSStub_4c3f {
  strings:
    $key_4c3f = { 18 57 [2] 6c 4f [2] 2b 4d [2] 6c 5c [2] 22 50 [2] 2e 5a [2] 39 51 [2] 22 1f [2] 1f }

  condition:
    any of them
}