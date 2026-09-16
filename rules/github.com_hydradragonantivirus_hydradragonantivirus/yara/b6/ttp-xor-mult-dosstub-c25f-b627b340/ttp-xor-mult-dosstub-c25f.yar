rule TTP_XOR_MULT_DOSStub_c25f {
  strings:
    $key_c25f = { 96 37 [2] e2 2f [2] a5 2d [2] e2 3c [2] ac 30 [2] a0 3a [2] b7 31 [2] ac 7f [2] 91 }

  condition:
    any of them
}