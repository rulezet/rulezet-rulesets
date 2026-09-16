rule TTP_XOR_MULT_DOSStub_e002 {
  strings:
    $key_e002 = { b4 6a [2] c0 72 [2] 87 70 [2] c0 61 [2] 8e 6d [2] 82 67 [2] 95 6c [2] 8e 22 [2] b3 }

  condition:
    any of them
}