rule TTP_XOR_MULT_DOSStub_c2b7 {
  strings:
    $key_c2b7 = { 96 df [2] e2 c7 [2] a5 c5 [2] e2 d4 [2] ac d8 [2] a0 d2 [2] b7 d9 [2] ac 97 [2] 91 }

  condition:
    any of them
}