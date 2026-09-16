rule TTP_XOR_MULT_DOSStub_b6eb {
  strings:
    $key_b6eb = { e2 83 [2] 96 9b [2] d1 99 [2] 96 88 [2] d8 84 [2] d4 8e [2] c3 85 [2] d8 cb [2] e5 }

  condition:
    any of them
}