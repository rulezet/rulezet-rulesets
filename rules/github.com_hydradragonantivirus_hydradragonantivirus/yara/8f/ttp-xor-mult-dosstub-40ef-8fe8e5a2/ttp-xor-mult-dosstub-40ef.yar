rule TTP_XOR_MULT_DOSStub_40ef {
  strings:
    $key_40ef = { 14 87 [2] 60 9f [2] 27 9d [2] 60 8c [2] 2e 80 [2] 22 8a [2] 35 81 [2] 2e cf [2] 13 }

  condition:
    any of them
}