rule TTP_XOR_MULT_DOSStub_65ef {
  strings:
    $key_65ef = { 31 87 [2] 45 9f [2] 02 9d [2] 45 8c [2] 0b 80 [2] 07 8a [2] 10 81 [2] 0b cf [2] 36 }

  condition:
    any of them
}