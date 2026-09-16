rule TTP_XOR_MULT_DOSStub_2efa {
  strings:
    $key_2efa = { 7a 92 [2] 0e 8a [2] 49 88 [2] 0e 99 [2] 40 95 [2] 4c 9f [2] 5b 94 [2] 40 da [2] 7d }

  condition:
    any of them
}