rule TTP_XOR_MULT_DOSStub_006f {
  strings:
    $key_006f = { 54 07 [2] 20 1f [2] 67 1d [2] 20 0c [2] 6e 00 [2] 62 0a [2] 75 01 [2] 6e 4f [2] 53 }

  condition:
    any of them
}