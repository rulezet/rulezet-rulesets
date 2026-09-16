rule TTP_XOR_MULT_DOSStub_b3e8 {
  strings:
    $key_b3e8 = { e7 80 [2] 93 98 [2] d4 9a [2] 93 8b [2] dd 87 [2] d1 8d [2] c6 86 [2] dd c8 [2] e0 }

  condition:
    any of them
}