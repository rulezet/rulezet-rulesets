rule TTP_XOR_MULT_DOSStub_5202 {
  strings:
    $key_5202 = { 06 6a [2] 72 72 [2] 35 70 [2] 72 61 [2] 3c 6d [2] 30 67 [2] 27 6c [2] 3c 22 [2] 01 }

  condition:
    any of them
}