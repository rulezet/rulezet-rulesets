rule TTP_XOR_MULT_DOSStub_b710 {
  strings:
    $key_b710 = { e3 78 [2] 97 60 [2] d0 62 [2] 97 73 [2] d9 7f [2] d5 75 [2] c2 7e [2] d9 30 [2] e4 }

  condition:
    any of them
}