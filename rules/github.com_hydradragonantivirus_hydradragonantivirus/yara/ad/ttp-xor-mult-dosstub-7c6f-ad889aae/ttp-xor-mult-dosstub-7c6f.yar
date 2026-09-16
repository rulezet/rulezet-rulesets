rule TTP_XOR_MULT_DOSStub_7c6f {
  strings:
    $key_7c6f = { 28 07 [2] 5c 1f [2] 1b 1d [2] 5c 0c [2] 12 00 [2] 1e 0a [2] 09 01 [2] 12 4f [2] 2f }

  condition:
    any of them
}