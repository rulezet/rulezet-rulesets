rule TTP_XOR_MULT_DOSStub_b302 {
  strings:
    $key_b302 = { e7 6a [2] 93 72 [2] d4 70 [2] 93 61 [2] dd 6d [2] d1 67 [2] c6 6c [2] dd 22 [2] e0 }

  condition:
    any of them
}