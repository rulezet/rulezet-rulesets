rule TTP_XOR_MULT_DOSStub_c260 {
  strings:
    $key_c260 = { 96 08 [2] e2 10 [2] a5 12 [2] e2 03 [2] ac 0f [2] a0 05 [2] b7 0e [2] ac 40 [2] 91 }

  condition:
    any of them
}