rule TTP_XOR_MULT_DOSStub_c256 {
  strings:
    $key_c256 = { 96 3e [2] e2 26 [2] a5 24 [2] e2 35 [2] ac 39 [2] a0 33 [2] b7 38 [2] ac 76 [2] 91 }

  condition:
    any of them
}