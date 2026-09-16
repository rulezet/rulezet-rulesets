rule TTP_XOR_MULT_DOSStub_b323 {
  strings:
    $key_b323 = { e7 4b [2] 93 53 [2] d4 51 [2] 93 40 [2] dd 4c [2] d1 46 [2] c6 4d [2] dd 03 [2] e0 }

  condition:
    any of them
}