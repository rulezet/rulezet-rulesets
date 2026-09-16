rule TTP_XOR_MULT_DOSStub_7c1f {
  strings:
    $key_7c1f = { 28 77 [2] 5c 6f [2] 1b 6d [2] 5c 7c [2] 12 70 [2] 1e 7a [2] 09 71 [2] 12 3f [2] 2f }

  condition:
    any of them
}