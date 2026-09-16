rule TTP_XOR_MULT_DOSStub_783f {
  strings:
    $key_783f = { 2c 57 [2] 58 4f [2] 1f 4d [2] 58 5c [2] 16 50 [2] 1a 5a [2] 0d 51 [2] 16 1f [2] 2b }

  condition:
    any of them
}