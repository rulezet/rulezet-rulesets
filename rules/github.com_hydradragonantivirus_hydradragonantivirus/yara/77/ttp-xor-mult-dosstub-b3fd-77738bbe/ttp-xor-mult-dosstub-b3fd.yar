rule TTP_XOR_MULT_DOSStub_b3fd {
  strings:
    $key_b3fd = { e7 95 [2] 93 8d [2] d4 8f [2] 93 9e [2] dd 92 [2] d1 98 [2] c6 93 [2] dd dd [2] e0 }

  condition:
    any of them
}