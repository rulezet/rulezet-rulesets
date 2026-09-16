rule TTP_XOR_MULT_DOSStub_10ef {
  strings:
    $key_10ef = { 44 87 [2] 30 9f [2] 77 9d [2] 30 8c [2] 7e 80 [2] 72 8a [2] 65 81 [2] 7e cf [2] 43 }

  condition:
    any of them
}