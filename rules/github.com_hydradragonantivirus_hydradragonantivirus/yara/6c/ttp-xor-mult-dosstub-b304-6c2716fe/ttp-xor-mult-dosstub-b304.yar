rule TTP_XOR_MULT_DOSStub_b304 {
  strings:
    $key_b304 = { e7 6c [2] 93 74 [2] d4 76 [2] 93 67 [2] dd 6b [2] d1 61 [2] c6 6a [2] dd 24 [2] e0 }

  condition:
    any of them
}