rule TTP_XOR_MULT_DOSStub_c250 {
  strings:
    $key_c250 = { 96 38 [2] e2 20 [2] a5 22 [2] e2 33 [2] ac 3f [2] a0 35 [2] b7 3e [2] ac 70 [2] 91 }

  condition:
    any of them
}