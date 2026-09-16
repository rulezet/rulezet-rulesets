rule TTP_XOR_MULT_DOSStub_c2f1 {
  strings:
    $key_c2f1 = { 96 99 [2] e2 81 [2] a5 83 [2] e2 92 [2] ac 9e [2] a0 94 [2] b7 9f [2] ac d1 [2] 91 }

  condition:
    any of them
}