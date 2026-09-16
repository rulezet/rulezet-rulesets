rule TTP_XOR_MULT_DOSStub_b32f {
  strings:
    $key_b32f = { e7 47 [2] 93 5f [2] d4 5d [2] 93 4c [2] dd 40 [2] d1 4a [2] c6 41 [2] dd 0f [2] e0 }

  condition:
    any of them
}