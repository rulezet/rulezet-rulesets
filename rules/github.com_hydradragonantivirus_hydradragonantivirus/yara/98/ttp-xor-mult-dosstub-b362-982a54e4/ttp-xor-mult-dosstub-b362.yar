rule TTP_XOR_MULT_DOSStub_b362 {
  strings:
    $key_b362 = { e7 0a [2] 93 12 [2] d4 10 [2] 93 01 [2] dd 0d [2] d1 07 [2] c6 0c [2] dd 42 [2] e0 }

  condition:
    any of them
}