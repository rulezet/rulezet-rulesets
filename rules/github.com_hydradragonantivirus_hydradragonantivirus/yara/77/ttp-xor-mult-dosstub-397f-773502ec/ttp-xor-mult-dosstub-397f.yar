rule TTP_XOR_MULT_DOSStub_397f {
  strings:
    $key_397f = { 6d 17 [2] 19 0f [2] 5e 0d [2] 19 1c [2] 57 10 [2] 5b 1a [2] 4c 11 [2] 57 5f [2] 6a }

  condition:
    any of them
}