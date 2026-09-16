rule TTP_XOR_MULT_DOSStub_1e6f {
  strings:
    $key_1e6f = { 4a 07 [2] 3e 1f [2] 79 1d [2] 3e 0c [2] 70 00 [2] 7c 0a [2] 6b 01 [2] 70 4f [2] 4d }

  condition:
    any of them
}