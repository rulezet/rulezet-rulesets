rule TTP_XOR_MULT_DOSStub_c25d {
  strings:
    $key_c25d = { 96 35 [2] e2 2d [2] a5 2f [2] e2 3e [2] ac 32 [2] a0 38 [2] b7 33 [2] ac 7d [2] 91 }

  condition:
    any of them
}