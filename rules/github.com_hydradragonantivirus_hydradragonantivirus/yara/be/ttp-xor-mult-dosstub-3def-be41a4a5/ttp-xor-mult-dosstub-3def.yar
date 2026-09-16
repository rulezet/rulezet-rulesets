rule TTP_XOR_MULT_DOSStub_3def {
  strings:
    $key_3def = { 69 87 [2] 1d 9f [2] 5a 9d [2] 1d 8c [2] 53 80 [2] 5f 8a [2] 48 81 [2] 53 cf [2] 6e }

  condition:
    any of them
}