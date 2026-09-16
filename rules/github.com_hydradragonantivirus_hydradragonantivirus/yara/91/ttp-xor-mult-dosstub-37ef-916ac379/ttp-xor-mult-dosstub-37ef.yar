rule TTP_XOR_MULT_DOSStub_37ef {
  strings:
    $key_37ef = { 63 87 [2] 17 9f [2] 50 9d [2] 17 8c [2] 59 80 [2] 55 8a [2] 42 81 [2] 59 cf [2] 64 }

  condition:
    any of them
}