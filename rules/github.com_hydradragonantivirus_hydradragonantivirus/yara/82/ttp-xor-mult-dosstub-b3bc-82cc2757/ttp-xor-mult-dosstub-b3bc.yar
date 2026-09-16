rule TTP_XOR_MULT_DOSStub_b3bc {
  strings:
    $key_b3bc = { e7 d4 [2] 93 cc [2] d4 ce [2] 93 df [2] dd d3 [2] d1 d9 [2] c6 d2 [2] dd 9c [2] e0 }

  condition:
    any of them
}