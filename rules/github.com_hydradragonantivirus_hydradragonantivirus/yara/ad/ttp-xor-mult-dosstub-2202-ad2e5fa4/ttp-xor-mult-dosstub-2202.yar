rule TTP_XOR_MULT_DOSStub_2202 {
  strings:
    $key_2202 = { 76 6a [2] 02 72 [2] 45 70 [2] 02 61 [2] 4c 6d [2] 40 67 [2] 57 6c [2] 4c 22 [2] 71 }

  condition:
    any of them
}