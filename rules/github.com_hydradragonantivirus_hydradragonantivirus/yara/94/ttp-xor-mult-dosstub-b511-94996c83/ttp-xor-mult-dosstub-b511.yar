rule TTP_XOR_MULT_DOSStub_b511 {
  strings:
    $key_b511 = { e1 79 [2] 95 61 [2] d2 63 [2] 95 72 [2] db 7e [2] d7 74 [2] c0 7f [2] db 31 [2] e6 }

  condition:
    any of them
}