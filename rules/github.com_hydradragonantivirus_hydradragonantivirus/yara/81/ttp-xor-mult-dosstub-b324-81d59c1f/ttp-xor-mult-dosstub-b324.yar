rule TTP_XOR_MULT_DOSStub_b324 {
  strings:
    $key_b324 = { e7 4c [2] 93 54 [2] d4 56 [2] 93 47 [2] dd 4b [2] d1 41 [2] c6 4a [2] dd 04 [2] e0 }

  condition:
    any of them
}