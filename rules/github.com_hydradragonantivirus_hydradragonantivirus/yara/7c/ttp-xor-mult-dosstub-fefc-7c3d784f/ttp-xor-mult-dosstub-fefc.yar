rule TTP_XOR_MULT_DOSStub_fefc {
  strings:
    $key_fefc = { aa 94 [2] de 8c [2] 99 8e [2] de 9f [2] 90 93 [2] 9c 99 [2] 8b 92 [2] 90 dc [2] ad }

  condition:
    any of them
}