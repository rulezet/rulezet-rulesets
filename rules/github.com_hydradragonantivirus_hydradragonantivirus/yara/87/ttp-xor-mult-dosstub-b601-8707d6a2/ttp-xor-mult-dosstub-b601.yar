rule TTP_XOR_MULT_DOSStub_b601 {
  strings:
    $key_b601 = { e2 69 [2] 96 71 [2] d1 73 [2] 96 62 [2] d8 6e [2] d4 64 [2] c3 6f [2] d8 21 [2] e5 }

  condition:
    any of them
}