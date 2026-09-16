rule TTP_XOR_MULT_DOSStub_6002 {
  strings:
    $key_6002 = { 34 6a [2] 40 72 [2] 07 70 [2] 40 61 [2] 0e 6d [2] 02 67 [2] 15 6c [2] 0e 22 [2] 33 }

  condition:
    any of them
}