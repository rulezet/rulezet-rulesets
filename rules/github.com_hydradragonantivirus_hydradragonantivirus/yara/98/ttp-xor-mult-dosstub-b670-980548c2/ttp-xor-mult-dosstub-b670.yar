rule TTP_XOR_MULT_DOSStub_b670 {
  strings:
    $key_b670 = { e2 18 [2] 96 00 [2] d1 02 [2] 96 13 [2] d8 1f [2] d4 15 [2] c3 1e [2] d8 50 [2] e5 }

  condition:
    any of them
}