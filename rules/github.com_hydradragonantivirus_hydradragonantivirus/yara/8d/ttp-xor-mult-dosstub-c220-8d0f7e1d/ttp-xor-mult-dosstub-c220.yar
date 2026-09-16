rule TTP_XOR_MULT_DOSStub_c220 {
  strings:
    $key_c220 = { 96 48 [2] e2 50 [2] a5 52 [2] e2 43 [2] ac 4f [2] a0 45 [2] b7 4e [2] ac 00 [2] 91 }

  condition:
    any of them
}