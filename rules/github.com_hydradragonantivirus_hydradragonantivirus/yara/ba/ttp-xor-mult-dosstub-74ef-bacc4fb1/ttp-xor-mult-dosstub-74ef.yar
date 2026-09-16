rule TTP_XOR_MULT_DOSStub_74ef {
  strings:
    $key_74ef = { 20 87 [2] 54 9f [2] 13 9d [2] 54 8c [2] 1a 80 [2] 16 8a [2] 01 81 [2] 1a cf [2] 27 }

  condition:
    any of them
}