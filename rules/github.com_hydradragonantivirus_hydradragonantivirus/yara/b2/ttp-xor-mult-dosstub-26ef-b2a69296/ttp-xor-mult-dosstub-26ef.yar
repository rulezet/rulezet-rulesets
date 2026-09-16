rule TTP_XOR_MULT_DOSStub_26ef {
  strings:
    $key_26ef = { 72 87 [2] 06 9f [2] 41 9d [2] 06 8c [2] 48 80 [2] 44 8a [2] 53 81 [2] 48 cf [2] 75 }

  condition:
    any of them
}