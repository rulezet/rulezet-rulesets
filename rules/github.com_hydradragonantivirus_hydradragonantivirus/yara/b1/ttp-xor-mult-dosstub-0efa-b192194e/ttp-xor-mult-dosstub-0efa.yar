rule TTP_XOR_MULT_DOSStub_0efa {
  strings:
    $key_0efa = { 5a 92 [2] 2e 8a [2] 69 88 [2] 2e 99 [2] 60 95 [2] 6c 9f [2] 7b 94 [2] 60 da [2] 5d }

  condition:
    any of them
}