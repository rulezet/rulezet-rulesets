rule TTP_XOR_MULT_DOSStub_c200 {
  strings:
    $key_c200 = { 96 68 [2] e2 70 [2] a5 72 [2] e2 63 [2] ac 6f [2] a0 65 [2] b7 6e [2] ac 20 [2] 91 }

  condition:
    any of them
}