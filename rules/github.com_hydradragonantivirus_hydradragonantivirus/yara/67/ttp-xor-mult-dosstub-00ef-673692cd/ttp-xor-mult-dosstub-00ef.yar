rule TTP_XOR_MULT_DOSStub_00ef {
  strings:
    $key_00ef = { 54 87 [2] 20 9f [2] 67 9d [2] 20 8c [2] 6e 80 [2] 62 8a [2] 75 81 [2] 6e cf [2] 53 }

  condition:
    any of them
}