rule TTP_XOR_MULT_DOSStub_fefa {
  strings:
    $key_fefa = { aa 92 [2] de 8a [2] 99 88 [2] de 99 [2] 90 95 [2] 9c 9f [2] 8b 94 [2] 90 da [2] ad }

  condition:
    any of them
}