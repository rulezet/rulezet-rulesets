rule TTP_XOR_MULT_DOSStub_c2e7 {
  strings:
    $key_c2e7 = { 96 8f [2] e2 97 [2] a5 95 [2] e2 84 [2] ac 88 [2] a0 82 [2] b7 89 [2] ac c7 [2] 91 }

  condition:
    any of them
}