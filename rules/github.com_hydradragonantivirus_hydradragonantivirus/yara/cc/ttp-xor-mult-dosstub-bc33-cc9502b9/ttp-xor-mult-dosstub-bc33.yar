rule TTP_XOR_MULT_DOSStub_bc33 {
  strings:
    $key_bc33 = { e8 5b [2] 9c 43 [2] db 41 [2] 9c 50 [2] d2 5c [2] de 56 [2] c9 5d [2] d2 13 [2] ef }

  condition:
    any of them
}