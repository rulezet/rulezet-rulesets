rule TTP_XOR_MULT_DOSStub_b61c {
  strings:
    $key_b61c = { e2 74 [2] 96 6c [2] d1 6e [2] 96 7f [2] d8 73 [2] d4 79 [2] c3 72 [2] d8 3c [2] e5 }

  condition:
    any of them
}