rule TTP_XOR_MULT_DOSStub_b352 {
  strings:
    $key_b352 = { e7 3a [2] 93 22 [2] d4 20 [2] 93 31 [2] dd 3d [2] d1 37 [2] c6 3c [2] dd 72 [2] e0 }

  condition:
    any of them
}