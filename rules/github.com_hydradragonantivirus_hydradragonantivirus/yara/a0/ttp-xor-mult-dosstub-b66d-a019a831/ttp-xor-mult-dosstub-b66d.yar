rule TTP_XOR_MULT_DOSStub_b66d {
  strings:
    $key_b66d = { e2 05 [2] 96 1d [2] d1 1f [2] 96 0e [2] d8 02 [2] d4 08 [2] c3 03 [2] d8 4d [2] e5 }

  condition:
    any of them
}