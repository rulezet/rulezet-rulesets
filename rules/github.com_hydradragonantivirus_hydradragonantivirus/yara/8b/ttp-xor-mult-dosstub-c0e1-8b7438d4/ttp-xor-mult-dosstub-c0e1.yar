rule TTP_XOR_MULT_DOSStub_c0e1 {
  strings:
    $key_c0e1 = { 94 89 [2] e0 91 [2] a7 93 [2] e0 82 [2] ae 8e [2] a2 84 [2] b5 8f [2] ae c1 [2] 93 }

  condition:
    any of them
}