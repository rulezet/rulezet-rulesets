rule TTP_XOR_MULT_DOSStub_c231 {
  strings:
    $key_c231 = { 96 59 [2] e2 41 [2] a5 43 [2] e2 52 [2] ac 5e [2] a0 54 [2] b7 5f [2] ac 11 [2] 91 }

  condition:
    any of them
}