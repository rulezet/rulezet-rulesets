rule TTP_XOR_MULT_DOSStub_03ef {
  strings:
    $key_03ef = { 57 87 [2] 23 9f [2] 64 9d [2] 23 8c [2] 6d 80 [2] 61 8a [2] 76 81 [2] 6d cf [2] 50 }

  condition:
    any of them
}