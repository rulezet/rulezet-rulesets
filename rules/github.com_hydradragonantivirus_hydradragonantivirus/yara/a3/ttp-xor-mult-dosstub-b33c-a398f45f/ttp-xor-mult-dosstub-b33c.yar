rule TTP_XOR_MULT_DOSStub_b33c {
  strings:
    $key_b33c = { e7 54 [2] 93 4c [2] d4 4e [2] 93 5f [2] dd 53 [2] d1 59 [2] c6 52 [2] dd 1c [2] e0 }

  condition:
    any of them
}