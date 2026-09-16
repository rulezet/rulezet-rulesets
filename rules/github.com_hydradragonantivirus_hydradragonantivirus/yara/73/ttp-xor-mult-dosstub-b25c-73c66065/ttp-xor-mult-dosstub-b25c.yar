rule TTP_XOR_MULT_DOSStub_b25c {
  strings:
    $key_b25c = { e6 34 [2] 92 2c [2] d5 2e [2] 92 3f [2] dc 33 [2] d0 39 [2] c7 32 [2] dc 7c [2] e1 }

  condition:
    any of them
}