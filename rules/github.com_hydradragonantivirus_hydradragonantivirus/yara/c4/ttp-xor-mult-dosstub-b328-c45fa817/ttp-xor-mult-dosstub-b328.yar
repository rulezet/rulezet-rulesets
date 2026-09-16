rule TTP_XOR_MULT_DOSStub_b328 {
  strings:
    $key_b328 = { e7 40 [2] 93 58 [2] d4 5a [2] 93 4b [2] dd 47 [2] d1 4d [2] c6 46 [2] dd 08 [2] e0 }

  condition:
    any of them
}