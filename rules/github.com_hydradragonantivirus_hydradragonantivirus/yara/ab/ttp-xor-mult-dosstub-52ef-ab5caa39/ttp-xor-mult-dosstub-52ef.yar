rule TTP_XOR_MULT_DOSStub_52ef {
  strings:
    $key_52ef = { 06 87 [2] 72 9f [2] 35 9d [2] 72 8c [2] 3c 80 [2] 30 8a [2] 27 81 [2] 3c cf [2] 01 }

  condition:
    any of them
}