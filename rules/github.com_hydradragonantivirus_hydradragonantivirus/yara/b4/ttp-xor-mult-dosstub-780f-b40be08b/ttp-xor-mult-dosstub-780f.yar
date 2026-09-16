rule TTP_XOR_MULT_DOSStub_780f {
  strings:
    $key_780f = { 2c 67 [2] 58 7f [2] 1f 7d [2] 58 6c [2] 16 60 [2] 1a 6a [2] 0d 61 [2] 16 2f [2] 2b }

  condition:
    any of them
}