rule TTP_XOR_MULT_DOSStub_38ef {
  strings:
    $key_38ef = { 6c 87 [2] 18 9f [2] 5f 9d [2] 18 8c [2] 56 80 [2] 5a 8a [2] 4d 81 [2] 56 cf [2] 6b }

  condition:
    any of them
}