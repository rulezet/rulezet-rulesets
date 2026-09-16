rule TTP_XOR_MULT_DOSStub_796f {
  strings:
    $key_796f = { 2d 07 [2] 59 1f [2] 1e 1d [2] 59 0c [2] 17 00 [2] 1b 0a [2] 0c 01 [2] 17 4f [2] 2a }

  condition:
    any of them
}