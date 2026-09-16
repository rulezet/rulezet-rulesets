rule TTP_XOR_MULT_DOSStub_c2e1 {
  strings:
    $key_c2e1 = { 96 89 [2] e2 91 [2] a5 93 [2] e2 82 [2] ac 8e [2] a0 84 [2] b7 8f [2] ac c1 [2] 91 }

  condition:
    any of them
}