rule TTP_XOR_MULT_DOSStub_4702 {
  strings:
    $key_4702 = { 13 6a [2] 67 72 [2] 20 70 [2] 67 61 [2] 29 6d [2] 25 67 [2] 32 6c [2] 29 22 [2] 14 }

  condition:
    any of them
}