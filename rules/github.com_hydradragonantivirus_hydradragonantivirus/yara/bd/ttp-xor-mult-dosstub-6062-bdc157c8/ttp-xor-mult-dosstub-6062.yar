rule TTP_XOR_MULT_DOSStub_6062 {
  strings:
    $key_6062 = { 34 0a [2] 40 12 [2] 07 10 [2] 40 01 [2] 0e 0d [2] 02 07 [2] 15 0c [2] 0e 42 [2] 33 }

  condition:
    any of them
}