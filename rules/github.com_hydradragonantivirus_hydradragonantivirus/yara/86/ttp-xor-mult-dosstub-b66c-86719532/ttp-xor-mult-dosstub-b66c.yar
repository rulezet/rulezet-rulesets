rule TTP_XOR_MULT_DOSStub_b66c {
  strings:
    $key_b66c = { e2 04 [2] 96 1c [2] d1 1e [2] 96 0f [2] d8 03 [2] d4 09 [2] c3 02 [2] d8 4c [2] e5 }

  condition:
    any of them
}