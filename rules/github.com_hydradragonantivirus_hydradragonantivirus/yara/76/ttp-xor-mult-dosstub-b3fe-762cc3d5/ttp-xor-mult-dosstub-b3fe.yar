rule TTP_XOR_MULT_DOSStub_b3fe {
  strings:
    $key_b3fe = { e7 96 [2] 93 8e [2] d4 8c [2] 93 9d [2] dd 91 [2] d1 9b [2] c6 90 [2] dd de [2] e0 }

  condition:
    any of them
}