rule TTP_XOR_MULT_DOSStub_b771 {
  strings:
    $key_b771 = { e3 19 [2] 97 01 [2] d0 03 [2] 97 12 [2] d9 1e [2] d5 14 [2] c2 1f [2] d9 51 [2] e4 }

  condition:
    any of them
}