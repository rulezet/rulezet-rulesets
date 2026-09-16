rule TTP_XOR_MULT_DOSStub_c25e {
  strings:
    $key_c25e = { 96 36 [2] e2 2e [2] a5 2c [2] e2 3d [2] ac 31 [2] a0 3b [2] b7 30 [2] ac 7e [2] 91 }

  condition:
    any of them
}