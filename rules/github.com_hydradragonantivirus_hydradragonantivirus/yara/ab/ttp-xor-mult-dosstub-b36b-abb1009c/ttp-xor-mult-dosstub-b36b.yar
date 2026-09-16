rule TTP_XOR_MULT_DOSStub_b36b {
  strings:
    $key_b36b = { e7 03 [2] 93 1b [2] d4 19 [2] 93 08 [2] dd 04 [2] d1 0e [2] c6 05 [2] dd 4b [2] e0 }

  condition:
    any of them
}