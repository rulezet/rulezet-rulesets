rule TTP_XOR_MULT_DOSStub_6202 {
  strings:
    $key_6202 = { 36 6a [2] 42 72 [2] 05 70 [2] 42 61 [2] 0c 6d [2] 00 67 [2] 17 6c [2] 0c 22 [2] 31 }

  condition:
    any of them
}