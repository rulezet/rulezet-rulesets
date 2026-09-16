rule TTP_XOR_MULT_DOSStub_c21f {
  strings:
    $key_c21f = { 96 77 [2] e2 6f [2] a5 6d [2] e2 7c [2] ac 70 [2] a0 7a [2] b7 71 [2] ac 3f [2] 91 }

  condition:
    any of them
}