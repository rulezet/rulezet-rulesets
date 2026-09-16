rule TTP_XOR_MULT_DOSStub_5209 {
  strings:
    $key_5209 = { 06 61 [2] 72 79 [2] 35 7b [2] 72 6a [2] 3c 66 [2] 30 6c [2] 27 67 [2] 3c 29 [2] 01 }

  condition:
    any of them
}