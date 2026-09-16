rule TTP_XOR_MULT_DOSStub_c24d {
  strings:
    $key_c24d = { 96 25 [2] e2 3d [2] a5 3f [2] e2 2e [2] ac 22 [2] a0 28 [2] b7 23 [2] ac 6d [2] 91 }

  condition:
    any of them
}