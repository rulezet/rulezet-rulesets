rule TTP_XOR_MULT_DOSStub_a7fd {
  strings:
    $key_a7fd = { f3 95 [2] 87 8d [2] c0 8f [2] 87 9e [2] c9 92 [2] c5 98 [2] d2 93 [2] c9 dd [2] f4 }

  condition:
    any of them
}