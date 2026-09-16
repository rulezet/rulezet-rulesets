rule TTP_XOR_MULT_DOSStub_b7fd {
  strings:
    $key_b7fd = { e3 95 [2] 97 8d [2] d0 8f [2] 97 9e [2] d9 92 [2] d5 98 [2] c2 93 [2] d9 dd [2] e4 }

  condition:
    any of them
}