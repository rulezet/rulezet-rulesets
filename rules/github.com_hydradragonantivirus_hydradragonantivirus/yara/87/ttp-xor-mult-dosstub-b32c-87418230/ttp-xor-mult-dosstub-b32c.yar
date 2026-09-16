rule TTP_XOR_MULT_DOSStub_b32c {
  strings:
    $key_b32c = { e7 44 [2] 93 5c [2] d4 5e [2] 93 4f [2] dd 43 [2] d1 49 [2] c6 42 [2] dd 0c [2] e0 }

  condition:
    any of them
}