rule TTP_XOR_MULT_DOSStub_21ef {
  strings:
    $key_21ef = { 75 87 [2] 01 9f [2] 46 9d [2] 01 8c [2] 4f 80 [2] 43 8a [2] 54 81 [2] 4f cf [2] 72 }

  condition:
    any of them
}