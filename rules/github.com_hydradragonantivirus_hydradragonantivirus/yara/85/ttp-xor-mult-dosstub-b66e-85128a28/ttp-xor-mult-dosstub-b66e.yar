rule TTP_XOR_MULT_DOSStub_b66e {
  strings:
    $key_b66e = { e2 06 [2] 96 1e [2] d1 1c [2] 96 0d [2] d8 01 [2] d4 0b [2] c3 00 [2] d8 4e [2] e5 }

  condition:
    any of them
}