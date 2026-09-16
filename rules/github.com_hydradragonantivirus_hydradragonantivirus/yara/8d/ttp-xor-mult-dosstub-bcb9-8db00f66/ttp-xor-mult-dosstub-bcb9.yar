rule TTP_XOR_MULT_DOSStub_bcb9 {
  strings:
    $key_bcb9 = { e8 d1 [2] 9c c9 [2] db cb [2] 9c da [2] d2 d6 [2] de dc [2] c9 d7 [2] d2 99 [2] ef }

  condition:
    any of them
}