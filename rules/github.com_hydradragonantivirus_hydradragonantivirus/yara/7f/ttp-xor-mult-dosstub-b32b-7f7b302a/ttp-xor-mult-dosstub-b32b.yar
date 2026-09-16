rule TTP_XOR_MULT_DOSStub_b32b {
  strings:
    $key_b32b = { e7 43 [2] 93 5b [2] d4 59 [2] 93 48 [2] dd 44 [2] d1 4e [2] c6 45 [2] dd 0b [2] e0 }

  condition:
    any of them
}