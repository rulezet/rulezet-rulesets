rule TTP_XOR_MULT_DOSStub_c210 {
  strings:
    $key_c210 = { 96 78 [2] e2 60 [2] a5 62 [2] e2 73 [2] ac 7f [2] a0 75 [2] b7 7e [2] ac 30 [2] 91 }

  condition:
    any of them
}