rule TTP_XOR_MULT_DOSStub_7def {
  strings:
    $key_7def = { 29 87 [2] 5d 9f [2] 1a 9d [2] 5d 8c [2] 13 80 [2] 1f 8a [2] 08 81 [2] 13 cf [2] 2e }

  condition:
    any of them
}