rule TTP_XOR_MULT_DOSStub_b6fd {
  strings:
    $key_b6fd = { e2 95 [2] 96 8d [2] d1 8f [2] 96 9e [2] d8 92 [2] d4 98 [2] c3 93 [2] d8 dd [2] e5 }

  condition:
    any of them
}