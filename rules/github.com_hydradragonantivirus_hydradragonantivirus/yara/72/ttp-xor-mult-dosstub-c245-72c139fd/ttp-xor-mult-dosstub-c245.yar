rule TTP_XOR_MULT_DOSStub_c245 {
  strings:
    $key_c245 = { 96 2d [2] e2 35 [2] a5 37 [2] e2 26 [2] ac 2a [2] a0 20 [2] b7 2b [2] ac 65 [2] 91 }

  condition:
    any of them
}