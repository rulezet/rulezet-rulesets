rule TTP_XOR_MULT_DOSStub_63ef {
  strings:
    $key_63ef = { 37 87 [2] 43 9f [2] 04 9d [2] 43 8c [2] 0d 80 [2] 01 8a [2] 16 81 [2] 0d cf [2] 30 }

  condition:
    any of them
}