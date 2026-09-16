rule TTP_XOR_MULT_DOSStub_c261 {
  strings:
    $key_c261 = { 96 09 [2] e2 11 [2] a5 13 [2] e2 02 [2] ac 0e [2] a0 04 [2] b7 0f [2] ac 41 [2] 91 }

  condition:
    any of them
}