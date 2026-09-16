rule TTP_XOR_MULT_DOSStub_3c6f {
  strings:
    $key_3c6f = { 68 07 [2] 1c 1f [2] 5b 1d [2] 1c 0c [2] 52 00 [2] 5e 0a [2] 49 01 [2] 52 4f [2] 6f }

  condition:
    any of them
}