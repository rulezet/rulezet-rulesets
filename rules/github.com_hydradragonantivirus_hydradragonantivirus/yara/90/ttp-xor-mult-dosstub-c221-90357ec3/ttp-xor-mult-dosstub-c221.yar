rule TTP_XOR_MULT_DOSStub_c221 {
  strings:
    $key_c221 = { 96 49 [2] e2 51 [2] a5 53 [2] e2 42 [2] ac 4e [2] a0 44 [2] b7 4f [2] ac 01 [2] 91 }

  condition:
    any of them
}