rule TTP_XOR_MULT_DOSStub_44ef {
  strings:
    $key_44ef = { 10 87 [2] 64 9f [2] 23 9d [2] 64 8c [2] 2a 80 [2] 26 8a [2] 31 81 [2] 2a cf [2] 17 }

  condition:
    any of them
}