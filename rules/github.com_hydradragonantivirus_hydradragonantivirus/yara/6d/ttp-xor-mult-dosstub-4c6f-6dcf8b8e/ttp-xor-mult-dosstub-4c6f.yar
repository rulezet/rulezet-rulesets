rule TTP_XOR_MULT_DOSStub_4c6f {
  strings:
    $key_4c6f = { 18 07 [2] 6c 1f [2] 2b 1d [2] 6c 0c [2] 22 00 [2] 2e 0a [2] 39 01 [2] 22 4f [2] 1f }

  condition:
    any of them
}