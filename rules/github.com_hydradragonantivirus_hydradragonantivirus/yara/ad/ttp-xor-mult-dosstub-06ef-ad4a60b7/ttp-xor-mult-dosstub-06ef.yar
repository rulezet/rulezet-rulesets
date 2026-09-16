rule TTP_XOR_MULT_DOSStub_06ef {
  strings:
    $key_06ef = { 52 87 [2] 26 9f [2] 61 9d [2] 26 8c [2] 68 80 [2] 64 8a [2] 73 81 [2] 68 cf [2] 55 }

  condition:
    any of them
}