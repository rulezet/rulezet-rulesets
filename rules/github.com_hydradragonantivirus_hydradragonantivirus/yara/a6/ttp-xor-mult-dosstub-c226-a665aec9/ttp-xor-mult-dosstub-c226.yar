rule TTP_XOR_MULT_DOSStub_c226 {
  strings:
    $key_c226 = { 96 4e [2] e2 56 [2] a5 54 [2] e2 45 [2] ac 49 [2] a0 43 [2] b7 48 [2] ac 06 [2] 91 }

  condition:
    any of them
}