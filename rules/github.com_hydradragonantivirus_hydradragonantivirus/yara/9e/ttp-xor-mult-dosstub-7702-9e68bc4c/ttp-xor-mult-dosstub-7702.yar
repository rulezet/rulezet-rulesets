rule TTP_XOR_MULT_DOSStub_7702 {
  strings:
    $key_7702 = { 23 6a [2] 57 72 [2] 10 70 [2] 57 61 [2] 19 6d [2] 15 67 [2] 02 6c [2] 19 22 [2] 24 }

  condition:
    any of them
}