rule TTP_XOR_MULT_DOSStub_feef {
  strings:
    $key_feef = { aa 87 [2] de 9f [2] 99 9d [2] de 8c [2] 90 80 [2] 9c 8a [2] 8b 81 [2] 90 cf [2] ad }

  condition:
    any of them
}