rule TTP_XOR_MULT_DOSStub_4efa {
  strings:
    $key_4efa = { 1a 92 [2] 6e 8a [2] 29 88 [2] 6e 99 [2] 20 95 [2] 2c 9f [2] 3b 94 [2] 20 da [2] 1d }

  condition:
    any of them
}