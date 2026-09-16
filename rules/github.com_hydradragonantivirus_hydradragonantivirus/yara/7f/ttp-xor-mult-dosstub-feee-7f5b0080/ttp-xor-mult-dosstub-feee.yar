rule TTP_XOR_MULT_DOSStub_feee {
  strings:
    $key_feee = { aa 86 [2] de 9e [2] 99 9c [2] de 8d [2] 90 81 [2] 9c 8b [2] 8b 80 [2] 90 ce [2] ad }

  condition:
    any of them
}